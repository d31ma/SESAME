package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
)

// Introspection is the RFC 7662 response.
//
// Every field other than Active is omitted when the token is not active. RFC
// 7662 section 2.2 is explicit about this and it is the right default: a
// caller holding a dead token learns only that it is dead.
type Introspection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	ID        string `json:"jti,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	SessionID string `json:"sid,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	// Thumbprint reports a DPoP key binding (RFC 9449). A resource server
	// that learns a token is bound but is told nothing about to what cannot
	// enforce the binding, so introspection reports it rather than hiding it:
	// the thumbprint is a public value derived from a public key.
	Thumbprint string `json:"dpop_thumbprint,omitempty"`
}

// Discovery builds the OpenID provider configuration for this deployment.
//
// The host names its own route paths because it owns every route; the engine
// turns them into absolute URLs under the configured issuer and refuses any
// that would leave that origin. Endpoints left empty take the conventional
// defaults.
func (s *Service) Discovery(endpoints oidcdomain.Endpoints) (oidcdomain.Metadata, error) {
	s.mu.Lock()
	issuer := s.issuer
	s.mu.Unlock()
	if issuer == "" {
		return oidcdomain.Metadata{}, ErrNoIssuer
	}

	defaults := oidcdomain.DefaultEndpoints()
	if endpoints.Authorization == "" {
		endpoints.Authorization = defaults.Authorization
	}
	if endpoints.Token == "" {
		endpoints.Token = defaults.Token
	}
	if endpoints.JWKS == "" {
		endpoints.JWKS = defaults.JWKS
	}
	if endpoints.Introspection == "" {
		endpoints.Introspection = defaults.Introspection
	}
	if endpoints.Revocation == "" {
		endpoints.Revocation = defaults.Revocation
	}
	if endpoints.EndSession == "" {
		endpoints.EndSession = defaults.EndSession
	}
	return oidcdomain.BuildMetadata(issuer, endpoints)
}

// Introspect reports whether a token is currently usable.
//
// This is the answer to the one thing a self-contained access token cannot
// tell a resource server: whether the authentication behind it still stands.
// A signature that verifies is not enough — the session may have been revoked
// or the principal suspended since, and introspection is where that shows up.
//
// The calling client must authenticate, and may only introspect tokens issued
// to itself. A resource server that is a distinct client cannot introspect on
// a token's behalf yet; that needs an audience/resource registration design
// rather than a looser rule here.
func (s *Service) Introspect(request TokenRequest, token string) (Introspection, error) {
	if err := oidcdomain.ValidateClientID(request.ClientID); err != nil {
		return Introspection{}, err
	}
	client, err := s.clientForTokenRequest(request)
	if err != nil {
		return Introspection{}, err
	}
	if token == "" {
		return Introspection{Active: false}, nil
	}

	if strings.HasPrefix(token, oidcdomain.RefreshIDPrefix) {
		return s.introspectRefresh(client, token), nil
	}
	return s.introspectAccess(client, token), nil
}

func (s *Service) introspectRefresh(client oidcClientRecord, token string) Introspection {
	tokenID, secret, found := cutCode(token)
	if !found {
		return Introspection{Active: false}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.refreshTokens[tokenID]
	if !exists || !oidcdomain.VerifyDigest(stored.SecretDigest, secret) || stored.ClientID != client.ID {
		return Introspection{Active: false}
	}
	now := s.now()
	family, familyExists := s.refreshFamilies[stored.FamilyID]
	if !familyExists || !family.Live(now) || !stored.Usable(now) {
		return Introspection{Active: false}
	}
	if !s.grantStandsLocked(stored.SessionID, stored.PrincipalID) {
		return Introspection{Active: false}
	}

	expiry := parseTimestamp(stored.ExpiresAt)
	return Introspection{
		Active:     true,
		Scope:      strings.Join(stored.Scopes, " "),
		ClientID:   stored.ClientID,
		Subject:    stored.PrincipalID,
		Issuer:     s.issuer,
		ExpiresAt:  expiry,
		IssuedAt:   parseTimestamp(stored.IssuedAt),
		ID:         stored.ID,
		TokenType:  "refresh_token",
		SessionID:  stored.SessionID,
		TenantID:   stored.TenantID,
		Thumbprint: stored.Thumbprint,
	}
}

func (s *Service) introspectAccess(client oidcClientRecord, compact string) Introspection {
	s.mu.Lock()
	signingKey := s.signingKey
	issuer := s.issuer
	now := s.now()
	s.mu.Unlock()
	if signingKey == nil || issuer == "" {
		return Introspection{Active: false}
	}

	// The audience is the calling client, so a token minted for someone else
	// fails verification rather than being reported on.
	claims, body, err := signingKey.Verify(compact, issuer, client.ID, now)
	if err != nil {
		return Introspection{Active: false}
	}

	sessionID, _ := body["sid"].(string)
	tenantID, _ := body["tenant_id"].(string)
	scope, _ := body["scope"].(string)
	thumbprint, _ := confirmationThumbprint(body)

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.grantStandsLocked(sessionID, claims.Subject) {
		return Introspection{Active: false}
	}
	if stored, exists := s.clients[client.ID]; !exists || stored.Client.Disabled {
		return Introspection{Active: false}
	}

	return Introspection{
		Active:     true,
		Scope:      scope,
		ClientID:   client.ID,
		Subject:    claims.Subject,
		Audience:   claims.Audience,
		Issuer:     claims.Issuer,
		Thumbprint: thumbprint,
		ExpiresAt:  claims.ExpiresAt,
		IssuedAt:   claims.IssuedAt,
		NotBefore:  claims.NotBefore,
		ID:         claims.ID,
		TokenType:  "Bearer",
		SessionID:  sessionID,
		TenantID:   tenantID,
	}
}

// grantStandsLocked reports whether the authentication a token speaks for is
// still in force. Session expiry is deliberately not fatal here for the same
// reason it is not fatal to a refresh: an access token has its own short
// lifetime, and offline access outlives the browser session by design.
// Revocation and suspension are what matter.
func (s *Service) grantStandsLocked(sessionID, principalID string) bool {
	session, exists := s.sessions[sessionID]
	if !exists || session.Status != sessiondomain.StatusActive {
		return false
	}
	principal, exists := s.principals[principalID]
	return exists && principal.Status == "active"
}

// Revoke implements RFC 7009 for the tokens SESAME can actually recall.
//
// A refresh token's whole family is revoked, which also ends the client's
// ability to mint further access tokens. An access token is a self-contained
// signed JWT and cannot be recalled; the honest way to end it early is to
// revoke the refresh family or the session behind it. Either way this returns
// the same acknowledgement, because RFC 7009 section 2.2 requires success for
// an unknown token too — distinguishing them would turn the endpoint into a
// token oracle.
func (s *Service) Revoke(ctx context.Context, request TokenRequest, token, actor string) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := oidcdomain.ValidateClientID(request.ClientID); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}
	client, err := s.clientForTokenRequest(request)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(token, oidcdomain.RefreshIDPrefix) {
		return nil
	}
	tokenID, secret, found := cutCode(token)
	if !found {
		return nil
	}

	s.mu.Lock()
	stored, exists := s.refreshTokens[tokenID]
	if !exists || !oidcdomain.VerifyDigest(stored.SecretDigest, secret) || stored.ClientID != client.ID {
		s.mu.Unlock()
		return nil
	}
	family, familyExists := s.refreshFamilies[stored.FamilyID]
	if !familyExists || family.Revoked {
		s.mu.Unlock()
		return nil
	}
	familyID := family.ID
	s.mu.Unlock()

	return s.RefreshFamilyRevoke(ctx, familyID, oidcdomain.RevokedReasonLogout, actor)
}

func parseTimestamp(value string) int64 {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0
	}
	return parsed.Unix()
}
