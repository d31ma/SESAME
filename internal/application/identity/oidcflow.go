package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

// Token lifetimes.
const (
	// AccessTokenLifetime is short because an access token is a bearer
	// credential that SESAME cannot recall once issued.
	AccessTokenLifetime = 5 * time.Minute
	// IDTokenLifetime matches it: an ID token is a statement about an
	// authentication event, not a session.
	IDTokenLifetime = 5 * time.Minute
)

// Stable OIDC flow errors.
var (
	ErrInteractionNotFound = errors.New("interaction not found")
	ErrInteractionClosed   = errors.New("interaction accepts no further steps")
	ErrInvalidGrant        = errors.New("authorization grant is not valid")
	ErrInvalidRedirectURI  = errors.New("redirect URI is not registered for this client")
	ErrScopeNotAllowed     = errors.New("scope is not registered for this client")
	ErrNoIssuer            = errors.New("no issuer is configured; set issuer in the deployment configuration")
)

// AuthorizationRequest is the authorization request a host received from a
// browser, handed here for validation before anything is shown to a user.
type AuthorizationRequest struct {
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	// RequestURI references a request already pushed and validated on the
	// back channel (RFC 9126). When it is present every other parameter but
	// ClientID must be absent: merging them would restore the tampering the
	// push exists to remove.
	RequestURI string `json:"request_uri,omitempty"`
}

// StartedInteraction is what the host needs to run the user-facing step. The
// secret is the only copy: it authorizes completing this interaction and is
// stored only as a digest.
type StartedInteraction struct {
	InteractionID string   `json:"interaction_id"`
	Secret        string   `json:"interaction_secret"`
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	ClientName    string   `json:"client_name"`
	Scopes        []string `json:"scopes"`
	ExpiresAt     string   `json:"expires_at"`
}

// AuthorizationResponse is what the host redirects the browser to. State is
// echoed back exactly as supplied so the client can match its own CSRF token.
type AuthorizationResponse struct {
	RedirectURI string `json:"redirect_uri"`
	Code        string `json:"code"`
	State       string `json:"state,omitempty"`
}

// TokenRequest is a back-channel token request. Code, RedirectURI, and
// CodeVerifier belong to the authorization code grant; RefreshToken and Scope
// belong to the refresh grant.
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// DeviceCode is the polling device's own credential, presented on the
	// device grant. It never travels through a browser.
	DeviceCode string `json:"device_code,omitempty"`
	// Scope may narrow the granted set on a refresh. It can never widen it.
	Scope string `json:"scope,omitempty"`
	// DPoPProof is the client's proof-of-possession JWT (RFC 9449). When it
	// is present the issued tokens are bound to its key; when it is absent
	// they are ordinary bearer tokens.
	DPoPProof string `json:"dpop_proof,omitempty"`
	// DPoPMethod and DPoPURI are the host's assertion about the HTTP request
	// it served. The engine speaks no HTTP and cannot observe them, so it
	// checks the proof against what the host reports — and separately checks
	// that what the host reports belongs to this deployment's issuer origin,
	// which is the part no careless host can undo.
	DPoPMethod string `json:"dpop_method,omitempty"`
	DPoPURI    string `json:"dpop_uri,omitempty"`
}

// TokenResponse is the issued token set. RefreshToken is present only when
// the grant carries offline_access.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// UseIssuer supplies the issuer identifier tokens are minted under. It comes
// from the deployment configuration; token issuance fails closed without it.
func (s *Service) UseIssuer(issuer string) {
	s.issuer = issuer
}

// AuthorizationStart validates a browser authorization request and persists
// the interaction the host will drive.
//
// Everything a later step could be lied about is fixed here: the redirect URI
// is matched exactly against the client's registration and stored, the scopes
// are checked against the registration, and the PKCE challenge is recorded.
// The token request cannot widen any of them afterwards.
func (s *Service) AuthorizationStart(
	ctx context.Context,
	request AuthorizationRequest,
	actor string,
) (StartedInteraction, error) {
	if err := s.requireLedger(); err != nil {
		return StartedInteraction{}, err
	}
	if err := oidcdomain.ValidateClientID(request.ClientID); err != nil {
		return StartedInteraction{}, err
	}
	if request.RequestURI != "" {
		// A pushed request was already validated on the back channel, so the
		// checks below would only re-run against parameters that must not be
		// there at all.
		return s.authorizationFromPushedRequest(ctx, request, actor)
	}
	if err := oidcdomain.ValidateResponseType(request.ResponseType); err != nil {
		return StartedInteraction{}, err
	}
	if err := oidcdomain.ValidateCodeChallenge(request.CodeChallenge, request.CodeChallengeMethod); err != nil {
		return StartedInteraction{}, err
	}
	if err := oidcdomain.ValidateState(request.State); err != nil {
		return StartedInteraction{}, err
	}
	if err := oidcdomain.ValidateNonce(request.Nonce); err != nil {
		return StartedInteraction{}, err
	}
	scopes, err := oidcdomain.NormalizeScopes(request.Scopes)
	if err != nil {
		return StartedInteraction{}, err
	}
	if actor == "" {
		return StartedInteraction{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	request.Scopes = scopes
	return s.startInteractionLocked(ctx, request, actor)
}

// startInteractionLocked persists one validated authorization request.
//
// Both entrances land here — the direct one and the pushed one — so a request
// that arrived by reference cannot be treated differently from one that
// arrived in the query string. Scopes are already normalised by the caller.
func (s *Service) startInteractionLocked(
	ctx context.Context,
	request AuthorizationRequest,
	actor string,
) (StartedInteraction, error) {
	id, err := oidcdomain.NewInteractionID()
	if err != nil {
		return StartedInteraction{}, err
	}
	secret, digest, err := oidcdomain.NewInteractionSecret()
	if err != nil {
		return StartedInteraction{}, err
	}

	stored, exists := s.clients[request.ClientID]
	if !exists || stored.Client.Disabled {
		// A disabled and an unknown client are one answer: an authorization
		// endpoint that distinguishes them enumerates registrations.
		return StartedInteraction{}, ErrClientNotFound
	}
	if !oidcdomain.MatchRedirectURI(stored.Client.RedirectURIs, request.RedirectURI) {
		return StartedInteraction{}, ErrInvalidRedirectURI
	}
	if allowed, offending := stored.Client.AllowsScopes(request.Scopes); !allowed {
		return StartedInteraction{}, fmt.Errorf("%w: %s", ErrScopeNotAllowed, offending)
	}

	now := s.now()
	event, err := s.ledger.Append(ctx, oidcdomain.EventInteractionStarted, stored.Client.TenantID, actor,
		oidcdomain.InteractionStartedPayload{
			InteractionID: id,
			TenantID:      stored.Client.TenantID,
			ClientID:      request.ClientID,
			RedirectURI:   request.RedirectURI,
			Scopes:        request.Scopes,
			State:         request.State,
			Nonce:         request.Nonce,
			CodeChallenge: request.CodeChallenge,
			CreatedAt:     now.Format(time.RFC3339Nano),
			ExpiresAt:     now.Add(oidcdomain.InteractionLifetime).Format(time.RFC3339Nano),
			SecretDigest:  digest,
		})
	if err != nil {
		return StartedInteraction{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyInteractionStarted(event); err != nil {
		return StartedInteraction{}, err
	}
	s.writeSnapshotLocked(ctx, id)

	interaction := s.interactions[id]
	return StartedInteraction{
		InteractionID: id,
		Secret:        secret,
		TenantID:      interaction.TenantID,
		ClientID:      interaction.ClientID,
		ClientName:    stored.Client.Name,
		Scopes:        interaction.Scopes,
		ExpiresAt:     interaction.ExpiresAt,
	}, nil
}

// AuthorizationComplete exchanges proof of an authenticated session for the
// authorization code.
//
// The session is verified here rather than trusted from the host: the host
// says which session it holds, and the engine decides whether that session is
// live, unrevoked, and inside the interaction's own tenant. A session from
// another tenant completes nothing.
func (s *Service) AuthorizationComplete(
	ctx context.Context,
	interactionID string,
	interactionSecret string,
	sessionID string,
	sessionSecret string,
	actor string,
) (AuthorizationResponse, error) {
	if err := s.requireLedger(); err != nil {
		return AuthorizationResponse{}, err
	}
	if err := oidcdomain.ValidateInteractionID(interactionID); err != nil {
		return AuthorizationResponse{}, err
	}
	if actor == "" {
		return AuthorizationResponse{}, errors.New("actor is required")
	}

	code, codeDigest, err := oidcdomain.NewAuthorizationCode()
	if err != nil {
		return AuthorizationResponse{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	interaction, exists := s.interactions[interactionID]
	// A wrong handle secret and an unknown interaction are one answer.
	if !exists || !oidcdomain.VerifyDigest(interaction.SecretDigest, interactionSecret) {
		return AuthorizationResponse{}, ErrInteractionNotFound
	}
	now := s.now()
	if !interaction.Pending(now) {
		return AuthorizationResponse{}, ErrInteractionClosed
	}

	session, err := s.verifySessionLocked(sessionID, sessionSecret, now)
	if err != nil {
		return AuthorizationResponse{}, err
	}
	if session.TenantID != interaction.TenantID {
		return AuthorizationResponse{}, ErrSessionNotFound
	}
	// A client whose registration was pulled while the user was logging in
	// gets nothing.
	stored, ok := s.clients[interaction.ClientID]
	if !ok || stored.Client.Disabled {
		return AuthorizationResponse{}, ErrClientNotFound
	}
	// Authentication proves who the user is; it does not prove they agreed to
	// this client holding these scopes. A third-party client needs that
	// recorded separately, and the check is against the scopes actually
	// requested rather than the ones the client is registered for.
	if satisfied, _ := s.consentSatisfiedLocked(
		stored.Client, session.PrincipalID, interaction.Scopes); !satisfied {
		return AuthorizationResponse{}, ErrConsentRequired
	}

	event, err := s.ledger.Append(ctx, oidcdomain.EventCodeIssued, interaction.TenantID, actor,
		oidcdomain.CodeIssuedPayload{
			InteractionID: interactionID,
			TenantID:      interaction.TenantID,
			PrincipalID:   session.PrincipalID,
			SessionID:     session.ID,
			Assurance:     session.Assurance,
			CodeDigest:    codeDigest,
			CodeExpiresAt: now.Add(oidcdomain.CodeLifetime).Format(time.RFC3339Nano),
		})
	if err != nil {
		return AuthorizationResponse{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyCodeIssued(event); err != nil {
		return AuthorizationResponse{}, err
	}
	s.writeSnapshotLocked(ctx, interactionID)

	return AuthorizationResponse{
		RedirectURI: interaction.RedirectURI,
		Code:        interactionID + "." + code,
		State:       interaction.State,
	}, nil
}

// TokenExchange redeems a grant for tokens. Both grants land here so that the
// client authentication, issuer, and signing-key preconditions are checked in
// exactly one place.
func (s *Service) TokenExchange(
	ctx context.Context,
	request TokenRequest,
	actor string,
) (TokenResponse, error) {
	if err := s.requireLedger(); err != nil {
		return TokenResponse{}, err
	}
	if err := oidcdomain.ValidateGrantType(request.GrantType); err != nil {
		return TokenResponse{}, err
	}
	if err := oidcdomain.ValidateClientID(request.ClientID); err != nil {
		return TokenResponse{}, err
	}
	if actor == "" {
		return TokenResponse{}, errors.New("actor is required")
	}
	if s.signingKey == nil {
		return TokenResponse{}, tokendomain.ErrNoSigningKey
	}
	if s.issuer == "" {
		return TokenResponse{}, ErrNoIssuer
	}
	switch request.GrantType {
	case oidcdomain.GrantTypeRefreshToken:
		return s.refreshExchange(ctx, request, actor)
	case oidcdomain.GrantTypeDeviceCode:
		return s.deviceCodeExchange(ctx, request, actor)
	}
	return s.codeExchange(ctx, request, actor)
}

func (s *Service) codeExchange(
	ctx context.Context,
	request TokenRequest,
	actor string,
) (TokenResponse, error) {
	if err := oidcdomain.ValidateCodeVerifier(request.CodeVerifier); err != nil {
		return TokenResponse{}, err
	}

	interactionID, secret, found := cutCode(request.Code)
	if !found {
		return TokenResponse{}, ErrInvalidGrant
	}

	// Confidential clients authenticate before the code is examined, so a
	// caller without the secret learns nothing about the code either way.
	// ClientAuthenticate takes the lock itself.
	client, err := s.clientForTokenRequest(request)
	if err != nil {
		return TokenResponse{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	interaction, exists := s.interactions[interactionID]
	if !exists || !oidcdomain.VerifyDigest(interaction.CodeDigest, secret) {
		return TokenResponse{}, ErrInvalidGrant
	}
	now := s.now()
	if !interaction.CodeUsable(now) {
		return TokenResponse{}, ErrInvalidGrant
	}
	// Every binding made at the authorization request is re-checked. A code
	// issued to one client, for one redirect URI, under one PKCE challenge,
	// is redeemable only under all three.
	if interaction.ClientID != client.ID ||
		interaction.RedirectURI != request.RedirectURI ||
		!oidcdomain.VerifyCodeVerifier(interaction.CodeChallenge, request.CodeVerifier) {
		return TokenResponse{}, ErrInvalidGrant
	}
	// A session revoked between login and token request stops the exchange:
	// the code speaks for an authentication that no longer stands.
	session, sessionExists := s.sessions[interaction.SessionID]
	if !sessionExists || !session.Active(now) {
		return TokenResponse{}, ErrInvalidGrant
	}
	principal, principalExists := s.principals[interaction.PrincipalID]
	if !principalExists || principal.Status != "active" {
		return TokenResponse{}, ErrInvalidGrant
	}

	// Spend the code before minting anything. If the ledger append fails the
	// caller gets an error and no token, which is the safe direction.
	event, err := s.ledger.Append(ctx, oidcdomain.EventCodeRedeemed, interaction.TenantID, actor,
		oidcdomain.CodeRedeemedPayload{
			InteractionID: interactionID,
			TenantID:      interaction.TenantID,
		})
	if err != nil {
		return TokenResponse{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyCodeRedeemed(event); err != nil {
		return TokenResponse{}, err
	}
	s.writeSnapshotLocked(ctx, interactionID)

	thumbprint, err := s.tokenRequestThumbprint(ctx, request, interaction.TenantID, actor)
	if err != nil {
		return TokenResponse{}, err
	}

	return s.issueTokensLocked(ctx, grantSubject{
		TenantID:    interaction.TenantID,
		ClientID:    interaction.ClientID,
		PrincipalID: interaction.PrincipalID,
		SessionID:   interaction.SessionID,
		Scopes:      interaction.Scopes,
		Assurance:   interaction.Assurance,
		Nonce:       interaction.Nonce,
		TokenID:     interaction.ID,
		Thumbprint:  thumbprint,
	}, "", now, actor)
}

// clientForTokenRequest authenticates a confidential client and refuses a
// secret offered by a public one.
func (s *Service) clientForTokenRequest(request TokenRequest) (oidcClientRecord, error) {
	s.mu.Lock()
	stored, exists := s.clients[request.ClientID]
	s.mu.Unlock()
	if !exists || stored.Client.Disabled {
		return oidcClientRecord{}, ErrClientNotFound
	}
	if stored.Client.Type == oidcdomain.TypeConfidential {
		client, err := s.ClientAuthenticate(request.ClientID, request.ClientSecret)
		if err != nil {
			return oidcClientRecord{}, err
		}
		return oidcClientRecord{ID: client.ID, TenantID: client.TenantID}, nil
	}
	if request.ClientSecret != "" {
		// A public client has no secret; one being offered means the caller
		// is confused about which client it is, and guessing is not a
		// service an authorization server should provide.
		return oidcClientRecord{}, ErrClientNotFound
	}
	return oidcClientRecord{ID: stored.Client.ID, TenantID: stored.Client.TenantID}, nil
}

// oidcClientRecord is the minimum a token exchange needs about a client.
type oidcClientRecord struct {
	ID       string
	TenantID string
}

// grantSubject is what a token set speaks for, whatever grant produced it.
// Both the code and refresh paths build one, so the two grants cannot drift
// into minting subtly different tokens.
type grantSubject struct {
	TenantID    string
	ClientID    string
	PrincipalID string
	SessionID   string
	Scopes      []string
	Assurance   string
	// Nonce is present only for an authorization code. An ID token minted
	// from a refresh must not carry one (OpenID Connect Core section 12.2):
	// it attests to no new authentication event.
	Nonce string
	// TokenID seeds the jti claims.
	TokenID string
	// Thumbprint binds the token to a client key (RFC 9449). Empty means an
	// ordinary bearer token.
	Thumbprint string
}

// issueTokensLocked mints the token set and, when the grant carries
// offline_access, a refresh token. familyID continues an existing rotating
// family; an empty familyID starts a new one.
func (s *Service) issueTokensLocked(
	ctx context.Context,
	subject grantSubject,
	familyID string,
	now time.Time,
	actor string,
) (TokenResponse, error) {
	scope := strings.Join(subject.Scopes, " ")

	access, err := s.signingKey.Sign(tokendomain.Claims{
		Issuer:    s.issuer,
		Subject:   subject.PrincipalID,
		Audience:  subject.ClientID,
		ExpiresAt: now.Add(AccessTokenLifetime).Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ID:        subject.TokenID,
		Extra:     accessClaims(subject, scope),
	})
	if err != nil {
		return TokenResponse{}, err
	}

	idClaims := tokendomain.Claims{
		Issuer:    s.issuer,
		Subject:   subject.PrincipalID,
		Audience:  subject.ClientID,
		ExpiresAt: now.Add(IDTokenLifetime).Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ID:        subject.TokenID + ".id",
		Extra: map[string]any{
			"sid":       subject.SessionID,
			"tenant_id": subject.TenantID,
			// acr carries how the principal proved identity, so a relying
			// party can require more than a password without asking SESAME.
			"acr": subject.Assurance,
		},
	}
	if subject.Nonce != "" {
		// The nonce binds this ID token to the authorization request that
		// asked for it, which is what stops an ID token being replayed into
		// a different login.
		idClaims.Extra["nonce"] = subject.Nonce
	}
	idToken, err := s.signingKey.Sign(idClaims)
	if err != nil {
		return TokenResponse{}, err
	}

	// A key-bound token is announced as a different type on purpose. A client
	// that hands a DPoP token to a resource server expecting `Bearer` should
	// fail loudly rather than have it accepted without the proof that is the
	// whole point of the binding.
	tokenType := "Bearer"
	if subject.Thumbprint != "" {
		tokenType = oidcdomain.TokenTypeDPoP
	}
	response := TokenResponse{
		AccessToken: access,
		IDToken:     idToken,
		TokenType:   tokenType,
		ExpiresIn:   int64(AccessTokenLifetime.Seconds()),
		Scope:       scope,
	}
	if !oidcdomain.GrantsOfflineAccess(subject.Scopes) {
		return response, nil
	}
	refresh, err := s.issueRefreshLocked(ctx, subject, familyID, now, actor)
	if err != nil {
		return TokenResponse{}, err
	}
	response.RefreshToken = refresh
	return response, nil
}

// accessClaims builds the access token's claims, including the confirmation
// claim when the grant is bound to a client key.
func accessClaims(subject grantSubject, scope string) map[string]any {
	claims := map[string]any{
		"scope": scope,
		"sid":   subject.SessionID,
		// The tenant is part of every decision input, so it is part of
		// every token a decision might be made from.
		"tenant_id": subject.TenantID,
	}
	if subject.Thumbprint != "" {
		claims[oidcdomain.DPoPConfirmationClaim] = map[string]any{
			oidcdomain.DPoPThumbprintClaim: subject.Thumbprint,
		}
	}
	return claims
}

// cutCode splits the issued code into its interaction handle and secret. The
// handle makes redemption a direct lookup instead of a scan, and the secret
// half is what is actually verified.
func cutCode(code string) (interactionID, secret string, found bool) {
	for index := 0; index < len(code); index++ {
		if code[index] == '.' {
			return code[:index], code[index+1:], true
		}
	}
	return "", "", false
}

// InteractionGet returns one interaction without its bearer digests, for
// operator diagnosis.
func (s *Service) InteractionGet(interactionID string) (oidcdomain.Interaction, error) {
	if err := oidcdomain.ValidateInteractionID(interactionID); err != nil {
		return oidcdomain.Interaction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	interaction, exists := s.interactions[interactionID]
	if !exists {
		return oidcdomain.Interaction{}, ErrInteractionNotFound
	}
	interaction.SecretDigest = ""
	interaction.CodeDigest = ""
	return interaction, nil
}

func (s *Service) applyInteractionStarted(event audit.Event) error {
	var payload oidcdomain.InteractionStartedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if err := s.admitInteraction(oidcdomain.Interaction{
		ID:            payload.InteractionID,
		TenantID:      payload.TenantID,
		ClientID:      payload.ClientID,
		RedirectURI:   payload.RedirectURI,
		Scopes:        payload.Scopes,
		State:         payload.State,
		Nonce:         payload.Nonce,
		CodeChallenge: payload.CodeChallenge,
		Status:        oidcdomain.InteractionAwaitingAuthentication,
		CreatedAt:     payload.CreatedAt,
		ExpiresAt:     payload.ExpiresAt,
		SecretDigest:  payload.SecretDigest,
	}); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	return nil
}

func (s *Service) applyCodeIssued(event audit.Event) error {
	var payload oidcdomain.CodeIssuedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	interaction, exists := s.interactions[payload.InteractionID]
	if !exists || interaction.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d names an unknown interaction", event.Sequence)
	}
	if interaction.Status != oidcdomain.InteractionAwaitingAuthentication {
		return fmt.Errorf("event sequence %d issues a second code for one interaction", event.Sequence)
	}
	interaction.Status = oidcdomain.InteractionCompleted
	interaction.PrincipalID = payload.PrincipalID
	interaction.SessionID = payload.SessionID
	interaction.Assurance = payload.Assurance
	interaction.CodeDigest = payload.CodeDigest
	interaction.CodeExpires = payload.CodeExpiresAt
	s.interactions[payload.InteractionID] = interaction
	return nil
}

func (s *Service) applyCodeRedeemed(event audit.Event) error {
	var payload oidcdomain.CodeRedeemedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	interaction, exists := s.interactions[payload.InteractionID]
	if !exists || interaction.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d names an unknown interaction", event.Sequence)
	}
	if interaction.CodeRedeemed {
		return fmt.Errorf("event sequence %d redeems a code twice", event.Sequence)
	}
	interaction.CodeRedeemed = true
	s.interactions[payload.InteractionID] = interaction
	return nil
}

func (s *Service) applyInteractionFailed(event audit.Event) error {
	var payload oidcdomain.InteractionFailedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	interaction, exists := s.interactions[payload.InteractionID]
	if !exists || interaction.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d names an unknown interaction", event.Sequence)
	}
	interaction.Status = oidcdomain.InteractionFailed
	s.interactions[payload.InteractionID] = interaction
	return nil
}

func (s *Service) admitInteraction(interaction oidcdomain.Interaction) error {
	if err := oidcdomain.ValidateInteractionID(interaction.ID); err != nil {
		return err
	}
	if err := tenantdomain.ValidateID(interaction.TenantID); err != nil {
		return err
	}
	if err := oidcdomain.ValidateClientID(interaction.ClientID); err != nil {
		return err
	}
	if _, exists := s.interactions[interaction.ID]; exists {
		return errors.New("duplicate interaction ID")
	}
	s.interactions[interaction.ID] = interaction
	return nil
}

// authorizationFromPushedRequest starts an interaction from a reference.
//
// The reference is spent before anything else happens, so it is consumed
// exactly once even if the interaction cannot be created. One that survived a
// failed authorization could be replayed by anything that saw the redirect.
func (s *Service) authorizationFromPushedRequest(
	ctx context.Context,
	request AuthorizationRequest,
	actor string,
) (StartedInteraction, error) {
	if carriesLooseParameters(request) {
		return StartedInteraction{}, ErrRequestURIConflict
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pushed, err := s.resolvePushedRequestLocked(ctx, request.RequestURI, request.ClientID, actor)
	if err != nil {
		return StartedInteraction{}, err
	}
	return s.startInteractionLocked(ctx, pushed, actor)
}
