package identity

import (
	"fmt"
	"sort"

	"github.com/d31ma/sesame/internal/domain/audit"
	scimdomain "github.com/d31ma/sesame/internal/domain/scim"
)

// scimUser is the provisioning record attached to a principal. Active is not
// stored here: the principal's status is the single source of truth, so an
// administrator's suspension and a provider's deactivation cannot disagree.
type scimUser struct {
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"scim_client_id"`
	ExternalID  string `json:"external_id,omitempty"`
	UserName    string `json:"user_name"`
	DisplayName string `json:"display_name,omitempty"`
}

// SCIMClientState is one provisioning client in a snapshot.
type SCIMClientState struct {
	Client      scimdomain.Client `json:"client"`
	TokenDigest string            `json:"token_digest"`
}

// SCIMUserState is one provisioning record in a snapshot.
type SCIMUserState struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"scim_client_id"`
	ExternalID  string `json:"external_id,omitempty"`
	UserName    string `json:"user_name"`
	DisplayName string `json:"display_name,omitempty"`
}

func (s *Service) applySCIMClientRegistered(event audit.Event) error {
	var payload scimdomain.ClientRegisteredPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.scimClients[payload.ClientID] = provisioningClient{
		Client: scimdomain.Client{
			ID:                  payload.ClientID,
			TenantID:            payload.TenantID,
			Name:                payload.Name,
			CanManageGroups:     payload.CanManageGroups,
			IdentifierNamespace: payload.IdentifierNamespace,
		},
		TokenDigest: payload.TokenDigest,
	}
	return nil
}

func (s *Service) applySCIMClientTokenRotated(event audit.Event) error {
	var payload scimdomain.ClientTokenRotatedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.scimClients[payload.ClientID]
	if !exists {
		return nil
	}
	stored.TokenDigest = payload.TokenDigest
	s.scimClients[payload.ClientID] = stored
	return nil
}

func (s *Service) applySCIMClientDisabled(event audit.Event) error {
	var payload scimdomain.ClientDisabledPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	stored, exists := s.scimClients[payload.ClientID]
	if !exists {
		return nil
	}
	stored.Client.Disabled = true
	s.scimClients[payload.ClientID] = stored
	return nil
}

func (s *Service) applySCIMUserProvisioned(event audit.Event) error {
	var payload scimdomain.UserProvisionedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.scimUsers[payload.PrincipalID] = scimUser{
		TenantID:    payload.TenantID,
		ClientID:    payload.ClientID,
		ExternalID:  payload.ExternalID,
		UserName:    payload.UserName,
		DisplayName: payload.DisplayName,
	}
	return nil
}

func (s *Service) applySCIMUserUpdated(event audit.Event) error {
	var payload scimdomain.UserUpdatedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.scimUsers[payload.PrincipalID] = scimUser{
		TenantID:    payload.TenantID,
		ClientID:    payload.ClientID,
		ExternalID:  payload.ExternalID,
		UserName:    payload.UserName,
		DisplayName: payload.DisplayName,
	}
	return nil
}

// applySCIMUserDeprovisioned records that a provider deactivated a user. The
// suspension itself is a principal event, so this only marks who asked.
func (s *Service) applySCIMUserDeprovisioned(event audit.Event) error {
	var payload scimdomain.UserDeprovisionedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	return nil
}

func (s *Service) exportSCIMClientsLocked() []SCIMClientState {
	clients := make([]SCIMClientState, 0, len(s.scimClients))
	for _, stored := range s.scimClients {
		clients = append(clients, SCIMClientState(stored))
	}
	sort.Slice(clients, func(left, right int) bool {
		return clients[left].Client.ID < clients[right].Client.ID
	})
	return clients
}

func (s *Service) exportSCIMUsersLocked() []SCIMUserState {
	users := make([]SCIMUserState, 0, len(s.scimUsers))
	for principalID, record := range s.scimUsers {
		users = append(users, SCIMUserState{
			PrincipalID: principalID,
			TenantID:    record.TenantID,
			ClientID:    record.ClientID,
			ExternalID:  record.ExternalID,
			UserName:    record.UserName,
			DisplayName: record.DisplayName,
		})
	}
	sort.Slice(users, func(left, right int) bool {
		return users[left].PrincipalID < users[right].PrincipalID
	})
	return users
}

func (s *Service) admitSCIMClient(restored SCIMClientState) error {
	if err := scimdomain.ValidateClientID(restored.Client.ID); err != nil {
		return err
	}
	s.scimClients[restored.Client.ID] = provisioningClient(restored)
	return nil
}

func (s *Service) admitSCIMUser(restored SCIMUserState) error {
	if restored.PrincipalID == "" || restored.UserName == "" {
		return fmt.Errorf("a provisioned user must name both a principal and a userName")
	}
	s.scimUsers[restored.PrincipalID] = scimUser{
		TenantID:    restored.TenantID,
		ClientID:    restored.ClientID,
		ExternalID:  restored.ExternalID,
		UserName:    restored.UserName,
		DisplayName: restored.DisplayName,
	}
	return nil
}
