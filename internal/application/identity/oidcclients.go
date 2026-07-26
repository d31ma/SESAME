package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/d31ma/sesame/internal/domain/audit"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
)

// Stable OIDC client errors.
var (
	ErrClientNotFound = errors.New("oidc client not found")
	ErrClientExists   = errors.New("oidc client name is already defined in this tenant")
	ErrClientDisabled = errors.New("oidc client is disabled")
)

// oidcClient is the projected client plus its one-way secret verifier. The
// verifier never leaves this package.
type oidcClient struct {
	Client   oidcdomain.Client
	Verifier string
}

// ClientRegistration reports a newly registered client. The secret is the
// only copy: it is stored as an Argon2id verifier and cannot be read back.
type ClientRegistration struct {
	Client oidcdomain.Client `json:"client"`
	Secret string            `json:"client_secret,omitempty"`
}

// ClientRegister defines a relying party. Client names are unique per tenant.
//
// A confidential client receives a generated secret, returned once. A public
// client receives none: it cannot keep one, so it is authenticated by its
// registered redirect URI and PKCE instead of by a secret every copy of the
// app would share.
func (s *Service) ClientRegister(
	ctx context.Context,
	tenantID string,
	name string,
	clientType string,
	redirectURIs []string,
	scopes []string,
	audience string,
	postLogoutRedirectURIs []string,
	actor string,
) (ClientRegistration, error) {
	if err := s.requireLedger(); err != nil {
		return ClientRegistration{}, err
	}
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return ClientRegistration{}, err
	}
	if err := oidcdomain.ValidateName(name); err != nil {
		return ClientRegistration{}, err
	}
	if err := oidcdomain.ValidateType(clientType); err != nil {
		return ClientRegistration{}, err
	}
	if audience == "" {
		// An omitted audience takes the stricter rule. A caller that has not
		// thought about consent gets the behaviour that asks the user.
		audience = oidcdomain.AudienceThirdParty
	}
	if err := oidcdomain.ValidateAudience(audience); err != nil {
		return ClientRegistration{}, err
	}
	normalizedURIs, err := oidcdomain.NormalizeRedirectURIs(redirectURIs)
	if err != nil {
		return ClientRegistration{}, err
	}
	normalizedScopes, err := oidcdomain.NormalizeScopes(scopes)
	if err != nil {
		return ClientRegistration{}, err
	}
	normalizedLogout, err := oidcdomain.NormalizePostLogoutRedirectURIs(postLogoutRedirectURIs)
	if err != nil {
		return ClientRegistration{}, err
	}
	if actor == "" {
		return ClientRegistration{}, errors.New("actor is required")
	}

	var secret, verifier string
	if clientType == oidcdomain.TypeConfidential {
		secret, err = oidcdomain.NewClientSecret()
		if err != nil {
			return ClientRegistration{}, err
		}
		// A client secret is compared, never read back, so it is hashed the
		// same way a password is.
		verifier, err = authenticatordomain.NewPasswordVerifier(secret)
		if err != nil {
			return ClientRegistration{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[tenantID]; !exists {
		return ClientRegistration{}, ErrNotFound
	}
	nameKey := identifierKey(tenantID, "oidc_client", name)
	if _, exists := s.clientNames[nameKey]; exists {
		return ClientRegistration{}, ErrClientExists
	}

	id, err := oidcdomain.NewClientID()
	if err != nil {
		return ClientRegistration{}, err
	}
	event, err := s.ledger.Append(ctx, oidcdomain.EventClientRegistered, tenantID, actor,
		oidcdomain.ClientRegisteredPayload{
			ClientID:               id,
			TenantID:               tenantID,
			Name:                   name,
			Type:                   clientType,
			RedirectURIs:           normalizedURIs,
			Scopes:                 normalizedScopes,
			Audience:               audience,
			PostLogoutRedirectURIs: normalizedLogout,
			SecretVerifier:         verifier,
		})
	if err != nil {
		return ClientRegistration{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyClientRegistered(event); err != nil {
		return ClientRegistration{}, err
	}
	s.writeSnapshotLocked(ctx, id)
	return ClientRegistration{Client: s.clients[id].Client, Secret: secret}, nil
}

// ClientGet returns one registered client. The secret verifier is not part of
// the returned record.
func (s *Service) ClientGet(clientID string) (oidcdomain.Client, error) {
	if err := oidcdomain.ValidateClientID(clientID); err != nil {
		return oidcdomain.Client{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, exists := s.clients[clientID]
	if !exists {
		return oidcdomain.Client{}, ErrClientNotFound
	}
	return stored.Client, nil
}

// ClientRotateSecret replaces a confidential client's secret. The previous
// secret stops working at the same moment, which is what makes this a usable
// response to a leak.
func (s *Service) ClientRotateSecret(ctx context.Context, clientID, actor string) (string, error) {
	if err := s.requireLedger(); err != nil {
		return "", err
	}
	if err := oidcdomain.ValidateClientID(clientID); err != nil {
		return "", err
	}
	if actor == "" {
		return "", errors.New("actor is required")
	}

	secret, err := oidcdomain.NewClientSecret()
	if err != nil {
		return "", err
	}
	verifier, err := authenticatordomain.NewPasswordVerifier(secret)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.clients[clientID]
	if !exists {
		return "", ErrClientNotFound
	}
	if stored.Client.Disabled {
		return "", ErrClientDisabled
	}
	if stored.Client.Type != oidcdomain.TypeConfidential {
		return "", errors.New("only a confidential client holds a secret")
	}

	event, err := s.ledger.Append(ctx, oidcdomain.EventClientSecretRotated, stored.Client.TenantID, actor,
		oidcdomain.ClientSecretRotatedPayload{
			ClientID:       clientID,
			TenantID:       stored.Client.TenantID,
			SecretVerifier: verifier,
		})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyClientSecretRotated(event); err != nil {
		return "", err
	}
	s.writeSnapshotLocked(ctx, clientID)
	return secret, nil
}

// ClientDisable durably stops a client. Disabling is idempotent so an
// operator responding to an incident can repeat it without a confusing
// failure, and it survives replay, rebuild, and restore.
func (s *Service) ClientDisable(ctx context.Context, clientID, reason, actor string) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := oidcdomain.ValidateClientID(clientID); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.clients[clientID]
	if !exists {
		return ErrClientNotFound
	}
	if stored.Client.Disabled {
		return nil
	}

	event, err := s.ledger.Append(ctx, oidcdomain.EventClientDisabled, stored.Client.TenantID, actor,
		oidcdomain.ClientDisabledPayload{
			ClientID: clientID,
			TenantID: stored.Client.TenantID,
			Reason:   reason,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyClientDisabled(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, clientID)
	return nil
}

// ClientAuthenticate verifies a confidential client's secret and returns the
// client. A disabled client never authenticates.
//
// A public client presents no secret; callers must still prove possession of
// the flow another way, which is what PKCE is for.
func (s *Service) ClientAuthenticate(clientID, secret string) (oidcdomain.Client, error) {
	if err := oidcdomain.ValidateClientID(clientID); err != nil {
		return oidcdomain.Client{}, err
	}

	s.mu.Lock()
	stored, exists := s.clients[clientID]
	verifier := stored.Verifier
	if !exists {
		// Verify against the process decoy so an unknown client ID costs the
		// same Argon2id work as a known one.
		verifier = s.decoyVerifier
	}
	s.mu.Unlock()

	matched, _, err := authenticatordomain.VerifyPassword(verifier, secret)
	if err != nil {
		return oidcdomain.Client{}, err
	}
	if !exists || !matched {
		return oidcdomain.Client{}, ErrClientNotFound
	}
	if stored.Client.Disabled {
		return oidcdomain.Client{}, ErrClientDisabled
	}
	if stored.Client.Type != oidcdomain.TypeConfidential {
		return oidcdomain.Client{}, ErrClientNotFound
	}
	return stored.Client, nil
}

func (s *Service) applyClientRegistered(event audit.Event) error {
	var payload oidcdomain.ClientRegisteredPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if err := s.admitClient(ClientState{
		Client: oidcdomain.Client{
			ID:                     payload.ClientID,
			TenantID:               payload.TenantID,
			Name:                   payload.Name,
			Type:                   payload.Type,
			RedirectURIs:           payload.RedirectURIs,
			Scopes:                 payload.Scopes,
			Audience:               payload.Audience,
			PostLogoutRedirectURIs: payload.PostLogoutRedirectURIs,
		},
		SecretVerifier: payload.SecretVerifier,
	}); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	return nil
}

func (s *Service) applyClientSecretRotated(event audit.Event) error {
	var payload oidcdomain.ClientSecretRotatedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.clients[payload.ClientID]
	if !exists || stored.Client.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d names an unknown client", event.Sequence)
	}
	stored.Verifier = payload.SecretVerifier
	s.clients[payload.ClientID] = stored
	return nil
}

func (s *Service) applyClientDisabled(event audit.Event) error {
	var payload oidcdomain.ClientDisabledPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.clients[payload.ClientID]
	if !exists || stored.Client.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d names an unknown client", event.Sequence)
	}
	stored.Client.Disabled = true
	s.clients[payload.ClientID] = stored
	return nil
}

func (s *Service) admitClient(state ClientState) error {
	if err := oidcdomain.ValidateClientID(state.Client.ID); err != nil {
		return err
	}
	if err := tenantdomain.ValidateID(state.Client.TenantID); err != nil {
		return err
	}
	if err := oidcdomain.ValidateName(state.Client.Name); err != nil {
		return err
	}
	if err := oidcdomain.ValidateType(state.Client.Type); err != nil {
		return err
	}
	// An audience recorded before consent existed replays as third party,
	// which is the stricter of the two rules.
	if state.Client.Audience == "" {
		state.Client.Audience = oidcdomain.AudienceThirdParty
	}
	if err := oidcdomain.ValidateAudience(state.Client.Audience); err != nil {
		return err
	}
	if _, err := oidcdomain.NormalizeRedirectURIs(state.Client.RedirectURIs); err != nil {
		return err
	}
	if _, err := oidcdomain.NormalizeScopes(state.Client.Scopes); err != nil {
		return err
	}
	if _, err := oidcdomain.NormalizePostLogoutRedirectURIs(state.Client.PostLogoutRedirectURIs); err != nil {
		return err
	}
	// A confidential client without a verifier could never authenticate, and
	// a public client with one implies a secret that does not exist.
	if (state.Client.Type == oidcdomain.TypeConfidential) != (state.SecretVerifier != "") {
		return fmt.Errorf("client %s has a secret verifier inconsistent with its type", state.Client.ID)
	}
	if _, exists := s.byID[state.Client.TenantID]; !exists {
		return fmt.Errorf("client %s belongs to unknown tenant", state.Client.ID)
	}
	if _, exists := s.clients[state.Client.ID]; exists {
		return errors.New("duplicate client ID")
	}
	nameKey := identifierKey(state.Client.TenantID, "oidc_client", state.Client.Name)
	if _, exists := s.clientNames[nameKey]; exists {
		return fmt.Errorf("client name %q is defined twice", state.Client.Name)
	}
	s.clients[state.Client.ID] = oidcClient{Client: state.Client, Verifier: state.SecretVerifier}
	s.clientNames[nameKey] = state.Client.ID
	return nil
}
