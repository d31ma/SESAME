package identity

import (
	"fmt"
	"sort"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	federationdomain "github.com/d31ma/sesame/internal/domain/federation"
)

// Projections for the federation slice.
//
// Each apply function is the single place one event type changes state, so
// replay from the ledger and replay from a snapshot tail cannot diverge.

func (s *Service) applyProviderRegistered(event audit.Event) error {
	var payload federationdomain.ProviderRegisteredPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.providers[payload.ProviderID] = federationProvider{
		Provider: federationdomain.Provider{
			ID:           payload.ProviderID,
			TenantID:     payload.TenantID,
			Name:         payload.Name,
			Issuer:       payload.Issuer,
			ClientID:     payload.ClientID,
			Scopes:       payload.Scopes,
			SubjectClaim: payload.SubjectClaim,
			EmailClaim:   payload.EmailClaim,
			Linking:      payload.Linking,
		},
		SecretSealed: payload.SecretSealed,
	}
	return nil
}

func (s *Service) applyProviderDisabled(event audit.Event) error {
	var payload federationdomain.ProviderDisabledPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.providers[payload.ProviderID]
	if !exists {
		return nil
	}
	stored.Provider.Disabled = true
	s.providers[payload.ProviderID] = stored
	return nil
}

func (s *Service) applyLoginStarted(event audit.Event) error {
	var payload federationdomain.LoginStartedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	createdAt, expiresAt, err := parseLoginTimes(payload)
	if err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	s.federatedLogins[payload.LoginID] = federationdomain.Login{
		ID:          payload.LoginID,
		TenantID:    payload.TenantID,
		ProviderID:  payload.ProviderID,
		Status:      federationdomain.LoginPending,
		StateDigest: payload.StateDigest,
		NonceDigest: payload.NonceDigest,
		RedirectURI: payload.RedirectURI,
		CreatedAt:   createdAt,
		ExpiresAt:   expiresAt,
	}
	s.federatedSecrets[payload.LoginID] = payload.SecretsSealed
	return nil
}

func parseLoginTimes(
	payload federationdomain.LoginStartedPayload,
) (time.Time, time.Time, error) {
	createdAt, err := time.Parse(time.RFC3339Nano, payload.CreatedAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("created_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, payload.ExpiresAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("expires_at: %w", err)
	}
	return createdAt, expiresAt, nil
}

func (s *Service) applyLoginCompleted(event audit.Event) error {
	var payload federationdomain.LoginCompletedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.closeLogin(payload.LoginID, federationdomain.LoginCompleted)
	// The link is recorded here as well as by EventSubjectLinked, because a
	// just-in-time provisioned principal is linked by the completion itself.
	s.federatedLinks[payload.SubjectHash] = payload.PrincipalID
	return nil
}

func (s *Service) applyLoginFailed(event audit.Event) error {
	var payload federationdomain.LoginFailedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.closeLogin(payload.LoginID, federationdomain.LoginFailed)
	return nil
}

// closeLogin marks a transaction spent and drops its secrets.
//
// The secrets go immediately: once a login is no longer pending they can
// never be needed again, and a sealed blob nobody will open is only a thing
// that can leak.
func (s *Service) closeLogin(loginID, status string) {
	login, exists := s.federatedLogins[loginID]
	if !exists {
		return
	}
	login.Status = status
	s.federatedLogins[loginID] = login
	delete(s.federatedSecrets, loginID)
}

func (s *Service) applySubjectLinked(event audit.Event) error {
	var payload federationdomain.SubjectLinkedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.federatedLinks[payload.SubjectHash] = payload.PrincipalID
	return nil
}

func (s *Service) applySubjectUnlinked(event audit.Event) error {
	var payload federationdomain.SubjectUnlinkedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	delete(s.federatedLinks, payload.SubjectHash)
	return nil
}

// exportProvidersLocked renders providers for a snapshot.
//
// Validated metadata and keys are deliberately absent: both are refetchable,
// and a stale copy restored from a snapshot would be worse than none, because
// it could pin SESAME to a key the provider has already rotated away.
func (s *Service) exportProvidersLocked() []ProviderState {
	providers := make([]ProviderState, 0, len(s.providers))
	for _, stored := range s.providers {
		providers = append(providers, ProviderState{
			Provider:     stored.Provider,
			SecretSealed: stored.SecretSealed,
		})
	}
	sort.Slice(providers, func(left, right int) bool {
		return providers[left].Provider.ID < providers[right].Provider.ID
	})
	return providers
}

// exportFederatedLinksLocked renders subject links for a snapshot.
func (s *Service) exportFederatedLinksLocked() []FederatedLinkState {
	links := make([]FederatedLinkState, 0, len(s.federatedLinks))
	for hash, principalID := range s.federatedLinks {
		links = append(links, FederatedLinkState{
			SubjectHash: hash,
			PrincipalID: principalID,
		})
	}
	sort.Slice(links, func(left, right int) bool {
		return links[left].SubjectHash < links[right].SubjectHash
	})
	return links
}

// admitProvider restores one provider from a snapshot.
func (s *Service) admitProvider(restored ProviderState) error {
	if err := federationdomain.ValidateProviderID(restored.Provider.ID); err != nil {
		return err
	}
	s.providers[restored.Provider.ID] = federationProvider{
		Provider:     restored.Provider,
		SecretSealed: restored.SecretSealed,
	}
	return nil
}

// admitFederatedLink restores one subject link from a snapshot.
func (s *Service) admitFederatedLink(restored FederatedLinkState) error {
	if restored.SubjectHash == "" || restored.PrincipalID == "" {
		return fmt.Errorf("a federated link must name both a subject hash and a principal")
	}
	s.federatedLinks[restored.SubjectHash] = restored.PrincipalID
	return nil
}

// exportFederatedLoginsLocked renders in-flight logins for a snapshot.
//
// Their sealed secrets are not exported. A login that survives a restart can
// still be reported and expired, but not completed: the state, nonce, and
// verifier are gone, so the exchange fails closed rather than proceeding
// without the nonce that binds the assertion to this attempt.
func (s *Service) exportFederatedLoginsLocked() []federationdomain.Login {
	logins := make([]federationdomain.Login, 0, len(s.federatedLogins))
	for _, login := range s.federatedLogins {
		logins = append(logins, login)
	}
	sort.Slice(logins, func(left, right int) bool {
		return logins[left].ID < logins[right].ID
	})
	return logins
}
