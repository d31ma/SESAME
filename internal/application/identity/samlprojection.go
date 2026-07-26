package identity

import (
	"fmt"
	"sort"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	samldomain "github.com/d31ma/sesame/internal/domain/saml"
)

// SAML login states. A transaction moves forward only.
const (
	samlLoginPending   = "pending"
	samlLoginCompleted = "completed"
	samlLoginFailed    = "failed"
)

// samlLogin is one in-flight SAML authentication.
//
// Unlike a federated OIDC login it holds no secrets: the request identifier
// travels in the AuthnRequest and its unguessability, not its
// confidentiality, is what binds an assertion to this attempt. That means a
// SAML login survives a restart fully usable, where a federated one cannot.
type samlLogin struct {
	ID         string    `json:"login_id"`
	TenantID   string    `json:"tenant_id"`
	ProviderID string    `json:"provider_id"`
	Status     string    `json:"status"`
	RequestID  string    `json:"request_id"`
	Recipient  string    `json:"recipient"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// SAMLProviderState is one provider in a snapshot.
type SAMLProviderState struct {
	Provider samldomain.Provider `json:"provider"`
}

// SAMLLinkState binds a SAML subject hash to a principal.
type SAMLLinkState struct {
	SubjectHash string `json:"subject_hash"`
	PrincipalID string `json:"principal_id"`
}

func (s *Service) applySAMLProviderRegistered(event audit.Event) error {
	var payload samldomain.ProviderRegisteredPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	return s.admitSAMLProvider(SAMLProviderState{Provider: samldomain.Provider{
		ID:                  payload.ProviderID,
		TenantID:            payload.TenantID,
		Name:                payload.Name,
		EntityID:            payload.EntityID,
		SSOURL:              payload.SSOURL,
		Certificates:        payload.Certificates,
		IdentifierNamespace: payload.IdentifierNamespace,
		Linking:             payload.Linking,
	}})
}

func (s *Service) applySAMLProviderDisabled(event audit.Event) error {
	var payload samldomain.ProviderDisabledPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.samlProviders[payload.ProviderID]
	if !exists {
		return nil
	}
	stored.Provider.Disabled = true
	s.samlProviders[payload.ProviderID] = stored
	return nil
}

func (s *Service) applySAMLLoginStarted(event audit.Event) error {
	var payload samldomain.LoginStartedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, payload.ExpiresAt)
	if err != nil {
		return fmt.Errorf("event sequence %d: expires_at: %w", event.Sequence, err)
	}
	s.samlLogins[payload.LoginID] = samlLogin{
		ID:         payload.LoginID,
		TenantID:   payload.TenantID,
		ProviderID: payload.ProviderID,
		Status:     samlLoginPending,
		RequestID:  payload.RequestID,
		Recipient:  payload.Recipient,
		ExpiresAt:  expiresAt,
	}
	return nil
}

func (s *Service) applySAMLLoginCompleted(event audit.Event) error {
	var payload samldomain.LoginCompletedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.closeSAMLLogin(payload.LoginID, samlLoginCompleted)
	s.samlLinks[payload.SubjectHash] = payload.PrincipalID
	// The replay claim replays too, so a restart cannot forget that an
	// assertion was already spent.
	s.samlReplay[payload.ReplayKey] = struct{}{}
	return nil
}

func (s *Service) applySAMLLoginFailed(event audit.Event) error {
	var payload samldomain.LoginFailedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.closeSAMLLogin(payload.LoginID, samlLoginFailed)
	return nil
}

func (s *Service) closeSAMLLogin(loginID, status string) {
	login, exists := s.samlLogins[loginID]
	if !exists {
		return
	}
	login.Status = status
	s.samlLogins[loginID] = login
}

// admitSAMLProvider parses the provider's certificates once, so every login
// does not re-parse them.
func (s *Service) admitSAMLProvider(restored SAMLProviderState) error {
	if err := samldomain.ValidateProviderID(restored.Provider.ID); err != nil {
		return err
	}
	certificates, err := samldomain.ParseCertificates(restored.Provider.Certificates)
	if err != nil {
		return fmt.Errorf("provider %s: %w", restored.Provider.ID, err)
	}
	s.samlProviders[restored.Provider.ID] = samlProvider{
		Provider: restored.Provider, Certificates: certificates,
	}
	return nil
}

func (s *Service) admitSAMLLink(restored SAMLLinkState) error {
	if restored.SubjectHash == "" || restored.PrincipalID == "" {
		return fmt.Errorf("a SAML link must name both a subject hash and a principal")
	}
	s.samlLinks[restored.SubjectHash] = restored.PrincipalID
	return nil
}

func (s *Service) exportSAMLProvidersLocked() []SAMLProviderState {
	providers := make([]SAMLProviderState, 0, len(s.samlProviders))
	for _, stored := range s.samlProviders {
		providers = append(providers, SAMLProviderState{Provider: stored.Provider})
	}
	sort.Slice(providers, func(left, right int) bool {
		return providers[left].Provider.ID < providers[right].Provider.ID
	})
	return providers
}

func (s *Service) exportSAMLLoginsLocked() []samlLogin {
	logins := make([]samlLogin, 0, len(s.samlLogins))
	for _, login := range s.samlLogins {
		logins = append(logins, login)
	}
	sort.Slice(logins, func(left, right int) bool { return logins[left].ID < logins[right].ID })
	return logins
}

func (s *Service) exportSAMLLinksLocked() []SAMLLinkState {
	links := make([]SAMLLinkState, 0, len(s.samlLinks))
	for hash, principalID := range s.samlLinks {
		links = append(links, SAMLLinkState{SubjectHash: hash, PrincipalID: principalID})
	}
	sort.Slice(links, func(left, right int) bool {
		return links[left].SubjectHash < links[right].SubjectHash
	})
	return links
}

// exportSAMLReplayLocked renders the spent-assertion claims.
//
// These must travel. An assertion spent before a restart that is forgotten
// after one is an assertion that can be replayed, and the whole point of
// single use is that a captured assertion is worth nothing twice.
func (s *Service) exportSAMLReplayLocked() []string {
	keys := make([]string, 0, len(s.samlReplay))
	for key := range s.samlReplay {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
