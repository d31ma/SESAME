package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/d31ma/sesame/internal/domain/audit"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// Stable consent errors.
var (
	// ErrConsentRequired reports an interaction that cannot issue a code
	// until the principal agrees. It is not a failure: the host is expected
	// to show a consent screen and come back.
	ErrConsentRequired = errors.New("consent is required for this client and scope set")
	// ErrConsentNotFound reports a query or withdrawal for a consent that
	// does not exist.
	ErrConsentNotFound = errors.New("consent not found")
)

// consentKey identifies one principal's standing agreement with one client.
func consentKey(principalID, clientID string) string {
	return principalID + "\x00" + clientID
}

// ConsentGrant records a principal agreeing that one client may hold one
// scope set.
//
// The session is verified here rather than trusted from the host, exactly as
// it is when completing an interaction: consent is a statement by a specific
// authenticated person, so the engine establishes who that is instead of
// accepting a principal ID from the caller.
//
// Re-granting merges with the existing set, so agreeing to one more scope
// does not silently drop the others.
func (s *Service) ConsentGrant(
	ctx context.Context,
	sessionID string,
	sessionSecret string,
	clientID string,
	scopes []string,
	actor string,
) (oidcdomain.Consent, error) {
	if err := s.requireLedger(); err != nil {
		return oidcdomain.Consent{}, err
	}
	if err := oidcdomain.ValidateClientID(clientID); err != nil {
		return oidcdomain.Consent{}, err
	}
	if err := oidcdomain.ValidateConsentScopes(scopes); err != nil {
		return oidcdomain.Consent{}, err
	}
	if actor == "" {
		return oidcdomain.Consent{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	session, err := s.verifySessionLocked(sessionID, sessionSecret, now)
	if err != nil {
		return oidcdomain.Consent{}, err
	}
	stored, exists := s.clients[clientID]
	if !exists || stored.Client.Disabled {
		return oidcdomain.Consent{}, ErrClientNotFound
	}
	if stored.Client.TenantID != session.TenantID {
		// Consenting across a tenant boundary would let one tenant's user
		// authorize another tenant's client.
		return oidcdomain.Consent{}, ErrClientNotFound
	}
	// A principal cannot agree to more than the client is registered for:
	// consent narrows what an administrator allowed, it never widens it.
	if allowed, offending := stored.Client.AllowsScopes(scopes); !allowed {
		return oidcdomain.Consent{}, fmt.Errorf("%w: %s", ErrScopeNotAllowed, offending)
	}

	key := consentKey(session.PrincipalID, clientID)
	agreed := scopes
	if existing, ok := s.consents[key]; ok && !existing.Withdrawn {
		agreed = oidcdomain.MergeScopes(existing.Scopes, scopes)
	}

	event, err := s.ledger.Append(ctx, oidcdomain.EventConsentGranted, session.TenantID, actor,
		oidcdomain.ConsentGrantedPayload{
			PrincipalID: session.PrincipalID,
			ClientID:    clientID,
			TenantID:    session.TenantID,
			Scopes:      agreed,
			GrantedAt:   oidcdomain.FormatConsentTime(now),
		})
	if err != nil {
		return oidcdomain.Consent{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyConsentGranted(event); err != nil {
		return oidcdomain.Consent{}, err
	}
	s.writeSnapshotLocked(ctx, clientID)
	return s.consents[key], nil
}

// ConsentWithdraw durably ends a principal's agreement with one client.
//
// Withdrawal is idempotent, and it does more than stop future authorizations:
// every refresh family this client holds for this principal is revoked in the
// same operation. A consent the user has taken back while the client keeps
// minting tokens from it would be a withdrawal in name only.
func (s *Service) ConsentWithdraw(
	ctx context.Context,
	principalID string,
	clientID string,
	actor string,
) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := principaldomain.ValidateID(principalID); err != nil {
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

	existing, exists := s.consents[consentKey(principalID, clientID)]
	if !exists {
		return ErrConsentNotFound
	}
	if existing.Withdrawn {
		return nil
	}

	event, err := s.ledger.Append(ctx, oidcdomain.EventConsentWithdrawn, existing.TenantID, actor,
		oidcdomain.ConsentWithdrawnPayload{
			PrincipalID: principalID,
			ClientID:    clientID,
			TenantID:    existing.TenantID,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyConsentWithdrawn(event); err != nil {
		return err
	}

	// Revoke every live family this client holds for this principal. Without
	// this the client keeps refreshing on an agreement that no longer exists.
	now := s.now()
	for _, token := range s.refreshTokens {
		if token.PrincipalID != principalID || token.ClientID != clientID {
			continue
		}
		family, ok := s.refreshFamilies[token.FamilyID]
		if !ok || !family.Live(now) {
			continue
		}
		if err := s.revokeFamilyLocked(ctx, family, "consent_withdrawn", actor); err != nil {
			return err
		}
	}
	s.writeSnapshotLocked(ctx, clientID)
	return nil
}

// ConsentGet returns one standing agreement.
func (s *Service) ConsentGet(principalID, clientID string) (oidcdomain.Consent, error) {
	if err := principaldomain.ValidateID(principalID); err != nil {
		return oidcdomain.Consent{}, err
	}
	if err := oidcdomain.ValidateClientID(clientID); err != nil {
		return oidcdomain.Consent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	consent, exists := s.consents[consentKey(principalID, clientID)]
	if !exists {
		return oidcdomain.Consent{}, ErrConsentNotFound
	}
	return consent, nil
}

// consentSatisfiedLocked reports whether an interaction may issue a code.
//
// A first-party client needs nothing: the administrator who registered it and
// the organization running the account are the same party. A third-party
// client needs a standing agreement covering every requested scope.
func (s *Service) consentSatisfiedLocked(
	client oidcdomain.Client,
	principalID string,
	scopes []string,
) (bool, string) {
	if !client.RequiresConsent() {
		return true, ""
	}
	consent, exists := s.consents[consentKey(principalID, client.ID)]
	if !exists {
		return false, ""
	}
	covered, offending := consent.Covers(scopes)
	return covered, offending
}

func (s *Service) applyConsentGranted(event audit.Event) error {
	var payload oidcdomain.ConsentGrantedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if err := oidcdomain.ValidateConsentScopes(payload.Scopes); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	s.consents[consentKey(payload.PrincipalID, payload.ClientID)] = oidcdomain.Consent{
		PrincipalID: payload.PrincipalID,
		ClientID:    payload.ClientID,
		TenantID:    payload.TenantID,
		Scopes:      payload.Scopes,
		GrantedAt:   payload.GrantedAt,
	}
	return nil
}

func (s *Service) applyConsentWithdrawn(event audit.Event) error {
	var payload oidcdomain.ConsentWithdrawnPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	key := consentKey(payload.PrincipalID, payload.ClientID)
	consent, exists := s.consents[key]
	if !exists || consent.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d names an unknown consent", event.Sequence)
	}
	consent.Withdrawn = true
	s.consents[key] = consent
	return nil
}

func (s *Service) admitConsent(consent oidcdomain.Consent) error {
	if err := principaldomain.ValidateID(consent.PrincipalID); err != nil {
		return err
	}
	if err := oidcdomain.ValidateClientID(consent.ClientID); err != nil {
		return err
	}
	key := consentKey(consent.PrincipalID, consent.ClientID)
	if _, exists := s.consents[key]; exists {
		return errors.New("duplicate consent")
	}
	s.consents[key] = consent
	return nil
}
