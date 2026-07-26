package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
)

// ErrRefreshFamilyNotFound reports a query for a family that does not exist.
var ErrRefreshFamilyNotFound = errors.New("refresh token family not found")

// refreshExchange rotates a refresh token.
//
// The presented token is spent and a successor issued in the same family. A
// legitimate client always holds the newest token, so a spent one arriving
// means two parties hold tokens from this family and one of them stole it.
// SESAME cannot tell which, so the whole family dies and the user
// re-authenticates.
func (s *Service) refreshExchange(
	ctx context.Context,
	request TokenRequest,
	actor string,
) (TokenResponse, error) {
	tokenID, secret, found := cutCode(request.RefreshToken)
	if !found {
		return TokenResponse{}, ErrInvalidGrant
	}

	// The client authenticates before the token is examined, so a caller
	// without the secret learns nothing about the token either way.
	client, err := s.clientForTokenRequest(request)
	if err != nil {
		return TokenResponse{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.refreshTokens[tokenID]
	if !exists || !oidcdomain.VerifyDigest(stored.SecretDigest, secret) {
		return TokenResponse{}, ErrInvalidGrant
	}
	// A token from one client is never redeemable by another, whatever
	// credentials that other client holds.
	if stored.ClientID != client.ID {
		return TokenResponse{}, ErrInvalidGrant
	}
	family, familyExists := s.refreshFamilies[stored.FamilyID]
	if !familyExists {
		return TokenResponse{}, ErrInvalidGrant
	}

	now := s.now()
	if stored.Spent {
		// Reuse detection. The whole family goes, including the successor a
		// legitimate client is holding right now — that client is sent back
		// through authentication, which is the correct cost when the
		// alternative is leaving a thief with a live grant.
		if family.Live(now) {
			if err := s.revokeFamilyLocked(ctx, family, oidcdomain.RevokedReasonReuse, actor); err != nil {
				return TokenResponse{}, err
			}
		}
		return TokenResponse{}, ErrInvalidGrant
	}
	if !stored.Usable(now) || !family.Live(now) {
		return TokenResponse{}, ErrInvalidGrant
	}

	// The grant is only as alive as the authentication behind it — but
	// "alive" here means unrevoked, not unexpired. offline_access exists
	// precisely for when the user's browser session is long gone; requiring
	// it to still be within its own lifetime would make the scope useless.
	// Revocation still bites, because that is a deliberate act of logout or
	// incident response rather than the passage of time.
	session, sessionExists := s.sessions[stored.SessionID]
	if !sessionExists || session.Status != sessiondomain.StatusActive {
		return TokenResponse{}, ErrInvalidGrant
	}
	principal, principalExists := s.principals[stored.PrincipalID]
	if !principalExists || principal.Status != "active" {
		return TokenResponse{}, ErrInvalidGrant
	}

	scopes, err := oidcdomain.NarrowScopes(stored.Scopes, splitScopes(request.Scope))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("%w: %v", ErrScopeNotAllowed, err)
	}

	// RFC 9449 section 7.1. A refresh token issued to a key stays tied to it
	// for the life of the family. The proof is required, and it has to be the
	// same key: without this a stolen refresh token could be exchanged for an
	// unbound bearer token, and the binding would be something an attacker
	// simply declines to carry forward.
	thumbprint, err := s.tokenRequestThumbprint(ctx, request, stored.TenantID, actor)
	if err != nil {
		return TokenResponse{}, err
	}
	if stored.Thumbprint != "" {
		if thumbprint == "" {
			return TokenResponse{}, ErrDPoPRequired
		}
		if thumbprint != stored.Thumbprint {
			return TokenResponse{}, oidcdomain.ErrDPoPKeyMismatch
		}
	}

	// Spend before minting. A failed append leaves the caller with an error
	// and no token, which is the safe direction.
	event, err := s.ledger.Append(ctx, oidcdomain.EventRefreshSpent, stored.TenantID, actor,
		oidcdomain.RefreshSpentPayload{
			RefreshTokenID: tokenID,
			FamilyID:       stored.FamilyID,
			TenantID:       stored.TenantID,
		})
	if err != nil {
		return TokenResponse{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyRefreshSpent(event); err != nil {
		return TokenResponse{}, err
	}

	response, err := s.issueTokensLocked(ctx, grantSubject{
		TenantID:    stored.TenantID,
		ClientID:    stored.ClientID,
		PrincipalID: stored.PrincipalID,
		SessionID:   stored.SessionID,
		Scopes:      scopes,
		Assurance:   stored.Assurance,
		TokenID:     tokenID,
		Thumbprint:  thumbprint,
	}, stored.FamilyID, now, actor)
	if err != nil {
		return TokenResponse{}, err
	}
	s.writeSnapshotLocked(ctx, stored.FamilyID)
	return response, nil
}

// issueRefreshLocked mints one refresh token, starting a family when
// familyID is empty.
func (s *Service) issueRefreshLocked(
	ctx context.Context,
	subject grantSubject,
	familyID string,
	now time.Time,
	actor string,
) (string, error) {
	tokenID, err := oidcdomain.NewRefreshID()
	if err != nil {
		return "", err
	}
	secret, digest, err := oidcdomain.NewRefreshSecret()
	if err != nil {
		return "", err
	}

	payload := oidcdomain.RefreshIssuedPayload{
		RefreshTokenID: tokenID,
		FamilyID:       familyID,
		TenantID:       subject.TenantID,
		ClientID:       subject.ClientID,
		PrincipalID:    subject.PrincipalID,
		SessionID:      subject.SessionID,
		Scopes:         subject.Scopes,
		Assurance:      subject.Assurance,
		IssuedAt:       now.Format(time.RFC3339Nano),
		ExpiresAt:      now.Add(oidcdomain.RefreshLifetime).Format(time.RFC3339Nano),
		Thumbprint:     subject.Thumbprint,
		SecretDigest:   digest,
	}
	if familyID == "" {
		payload.FamilyID, err = oidcdomain.NewRefreshFamilyID()
		if err != nil {
			return "", err
		}
		// The absolute ceiling is written once, on the event that starts the
		// family, so no rotation can quietly extend it.
		payload.FamilyExpiresAt = now.Add(oidcdomain.RefreshFamilyLifetime).Format(time.RFC3339Nano)
	}

	event, err := s.ledger.Append(ctx, oidcdomain.EventRefreshIssued, subject.TenantID, actor, payload)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyRefreshIssued(event); err != nil {
		return "", err
	}
	return tokenID + "." + secret, nil
}

// RefreshFamilyRevoke durably ends every token descended from one
// authorization. This is the logout primitive: revoking the session stops new
// access tokens, and revoking the family stops the client minting more.
//
// Revoking an already revoked family is idempotent, so an incident response
// can be retried.
func (s *Service) RefreshFamilyRevoke(ctx context.Context, familyID, reason, actor string) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := oidcdomain.ValidateRefreshFamilyID(familyID); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}
	if reason == "" {
		reason = oidcdomain.RevokedReasonLogout
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	family, exists := s.refreshFamilies[familyID]
	if !exists {
		return ErrRefreshFamilyNotFound
	}
	if family.Revoked {
		return nil
	}
	if err := s.revokeFamilyLocked(ctx, family, reason, actor); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, familyID)
	return nil
}

func (s *Service) revokeFamilyLocked(
	ctx context.Context,
	family oidcdomain.RefreshFamily,
	reason string,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, oidcdomain.EventRefreshFamilyRevoked, family.TenantID, actor,
		oidcdomain.RefreshFamilyRevokedPayload{
			FamilyID: family.ID,
			TenantID: family.TenantID,
			Reason:   reason,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applyRefreshFamilyRevoked(event)
}

// RefreshFamilyGet returns one family for operator diagnosis. It carries no
// token material at all.
func (s *Service) RefreshFamilyGet(familyID string) (oidcdomain.RefreshFamily, error) {
	if err := oidcdomain.ValidateRefreshFamilyID(familyID); err != nil {
		return oidcdomain.RefreshFamily{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	family, exists := s.refreshFamilies[familyID]
	if !exists {
		return oidcdomain.RefreshFamily{}, ErrRefreshFamilyNotFound
	}
	return family, nil
}

// splitScopes parses a space-delimited OAuth scope parameter.
func splitScopes(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

func (s *Service) applyRefreshIssued(event audit.Event) error {
	var payload oidcdomain.RefreshIssuedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if err := oidcdomain.ValidateRefreshID(payload.RefreshTokenID); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	if err := oidcdomain.ValidateRefreshFamilyID(payload.FamilyID); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	if err := tenantdomain.ValidateID(payload.TenantID); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	if _, exists := s.refreshTokens[payload.RefreshTokenID]; exists {
		return fmt.Errorf("event sequence %d issues a duplicate refresh token", event.Sequence)
	}

	family, exists := s.refreshFamilies[payload.FamilyID]
	switch {
	case !exists:
		if payload.FamilyExpiresAt == "" {
			return fmt.Errorf("event sequence %d starts a family with no ceiling", event.Sequence)
		}
		s.refreshFamilies[payload.FamilyID] = oidcdomain.RefreshFamily{
			ID:        payload.FamilyID,
			TenantID:  payload.TenantID,
			ClientID:  payload.ClientID,
			SessionID: payload.SessionID,
			StartedAt: payload.IssuedAt,
			ExpiresAt: payload.FamilyExpiresAt,
		}
	case payload.FamilyExpiresAt != "":
		// A rotation that carried a new ceiling would extend the family past
		// its absolute bound, so it is refused rather than applied.
		return fmt.Errorf("event sequence %d re-declares an existing family ceiling", event.Sequence)
	case family.Revoked:
		return fmt.Errorf("event sequence %d issues into a revoked family", event.Sequence)
	}

	s.refreshTokens[payload.RefreshTokenID] = oidcdomain.RefreshToken{
		ID:           payload.RefreshTokenID,
		FamilyID:     payload.FamilyID,
		TenantID:     payload.TenantID,
		ClientID:     payload.ClientID,
		PrincipalID:  payload.PrincipalID,
		SessionID:    payload.SessionID,
		Scopes:       payload.Scopes,
		Assurance:    payload.Assurance,
		IssuedAt:     payload.IssuedAt,
		ExpiresAt:    payload.ExpiresAt,
		Thumbprint:   payload.Thumbprint,
		SecretDigest: payload.SecretDigest,
	}
	return nil
}

func (s *Service) applyRefreshSpent(event audit.Event) error {
	var payload oidcdomain.RefreshSpentPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.refreshTokens[payload.RefreshTokenID]
	if !exists || stored.TenantID != payload.TenantID || stored.FamilyID != payload.FamilyID {
		return fmt.Errorf("event sequence %d names an unknown refresh token", event.Sequence)
	}
	if stored.Spent {
		return fmt.Errorf("event sequence %d spends a refresh token twice", event.Sequence)
	}
	stored.Spent = true
	s.refreshTokens[payload.RefreshTokenID] = stored
	return nil
}

func (s *Service) applyRefreshFamilyRevoked(event audit.Event) error {
	var payload oidcdomain.RefreshFamilyRevokedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	family, exists := s.refreshFamilies[payload.FamilyID]
	if !exists || family.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d names an unknown refresh family", event.Sequence)
	}
	family.Revoked = true
	family.Reason = payload.Reason
	s.refreshFamilies[payload.FamilyID] = family
	return nil
}

func (s *Service) admitRefreshFamily(family oidcdomain.RefreshFamily) error {
	if err := oidcdomain.ValidateRefreshFamilyID(family.ID); err != nil {
		return err
	}
	if err := tenantdomain.ValidateID(family.TenantID); err != nil {
		return err
	}
	if _, exists := s.refreshFamilies[family.ID]; exists {
		return errors.New("duplicate refresh family ID")
	}
	s.refreshFamilies[family.ID] = family
	return nil
}

func (s *Service) admitRefreshToken(token oidcdomain.RefreshToken) error {
	if err := oidcdomain.ValidateRefreshID(token.ID); err != nil {
		return err
	}
	if _, exists := s.refreshFamilies[token.FamilyID]; !exists {
		return fmt.Errorf("refresh token %s belongs to unknown family", token.ID)
	}
	if _, exists := s.refreshTokens[token.ID]; exists {
		return errors.New("duplicate refresh token ID")
	}
	s.refreshTokens[token.ID] = token
	return nil
}
