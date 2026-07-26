package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/d31ma/sesame/internal/domain/audit"
	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
)

// Stable group errors.
var (
	ErrGroupNotFound       = errors.New("group not found")
	ErrGroupExists         = errors.New("group name is already defined in this tenant")
	ErrGroupMemberExists   = errors.New("principal is already a member of this group")
	ErrGroupMemberNotFound = errors.New("principal is not a member of this group")
)

// GroupCreate defines a named group. Group names are unique per tenant.
func (s *Service) GroupCreate(
	ctx context.Context,
	tenantID string,
	name string,
	actor string,
) (authzdomain.Group, error) {
	if err := s.requireLedger(); err != nil {
		return authzdomain.Group{}, err
	}
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return authzdomain.Group{}, err
	}
	normalized := tenantdomain.NormalizeName(name)
	if err := tenantdomain.ValidateName(normalized); err != nil {
		return authzdomain.Group{}, fmt.Errorf("group name: %w", err)
	}
	if actor == "" {
		return authzdomain.Group{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[tenantID]; !exists {
		return authzdomain.Group{}, ErrNotFound
	}
	if _, exists := s.groupNames[identifierKey(tenantID, "group", normalized)]; exists {
		return authzdomain.Group{}, ErrGroupExists
	}

	id, err := authzdomain.NewGroupID()
	if err != nil {
		return authzdomain.Group{}, err
	}
	event, err := s.ledger.Append(ctx, authzdomain.EventGroupCreated, tenantID, actor, authzdomain.GroupCreatedPayload{
		GroupID:  id,
		TenantID: tenantID,
		Name:     normalized,
	})
	if err != nil {
		return authzdomain.Group{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyGroupCreated(event); err != nil {
		return authzdomain.Group{}, err
	}
	s.writeSnapshotLocked(ctx, id)
	return s.groups[id], nil
}

// GroupGetByName returns one group by normalized name inside a tenant.
func (s *Service) GroupGetByName(tenantID, name string) (authzdomain.Group, error) {
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return authzdomain.Group{}, err
	}
	normalized := tenantdomain.NormalizeName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	id, exists := s.groupNames[identifierKey(tenantID, "group", normalized)]
	if !exists {
		return authzdomain.Group{}, ErrGroupNotFound
	}
	return s.groups[id], nil
}

// GroupMemberAdd records a principal joining a group.
func (s *Service) GroupMemberAdd(ctx context.Context, groupID, principalID, actor string) error {
	return s.groupMembership(ctx, authzdomain.EventGroupMemberAdded, groupID, principalID, actor)
}

// GroupMemberRemove durably removes a principal from a group; decisions
// resolved through this membership deny after replay, rebuild, and restore.
func (s *Service) GroupMemberRemove(ctx context.Context, groupID, principalID, actor string) error {
	return s.groupMembership(ctx, authzdomain.EventGroupMemberRemoved, groupID, principalID, actor)
}

func (s *Service) groupMembership(
	ctx context.Context,
	eventType string,
	groupID string,
	principalID string,
	actor string,
) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := authzdomain.ValidateGroupID(groupID); err != nil {
		return err
	}
	if err := principaldomain.ValidateID(principalID); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	group, exists := s.groups[groupID]
	if !exists {
		return ErrGroupNotFound
	}
	principal, exists := s.principals[principalID]
	if !exists || principal.TenantID != group.TenantID {
		return ErrPrincipalNotFound
	}
	_, isMember := s.memberships[groupID][principalID]
	if eventType == authzdomain.EventGroupMemberAdded && isMember {
		return ErrGroupMemberExists
	}
	if eventType == authzdomain.EventGroupMemberRemoved && !isMember {
		return ErrGroupMemberNotFound
	}

	event, err := s.ledger.Append(ctx, eventType, group.TenantID, actor, authzdomain.GroupMemberPayload{
		GroupID:     groupID,
		TenantID:    group.TenantID,
		PrincipalID: principalID,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyGroupMembership(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, groupID)
	return nil
}

// GrantCreateForGroup assigns a role to every present and future member of a
// group.
func (s *Service) GrantCreateForGroup(
	ctx context.Context,
	tenantID string,
	groupID string,
	roleID string,
	actor string,
) (authzdomain.Grant, error) {
	if err := s.requireLedger(); err != nil {
		return authzdomain.Grant{}, err
	}
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return authzdomain.Grant{}, err
	}
	if err := authzdomain.ValidateGroupID(groupID); err != nil {
		return authzdomain.Grant{}, err
	}
	if err := authzdomain.ValidateRoleID(roleID); err != nil {
		return authzdomain.Grant{}, err
	}
	if actor == "" {
		return authzdomain.Grant{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[tenantID]; !exists {
		return authzdomain.Grant{}, ErrNotFound
	}
	group, exists := s.groups[groupID]
	if !exists || group.TenantID != tenantID {
		return authzdomain.Grant{}, ErrGroupNotFound
	}
	role, exists := s.roles[roleID]
	if !exists || role.TenantID != tenantID {
		return authzdomain.Grant{}, ErrRoleNotFound
	}
	if _, exists := s.grantKeys[identifierKey(tenantID, groupID, roleID)]; exists {
		return authzdomain.Grant{}, ErrGrantExists
	}

	id, err := authzdomain.NewGrantID()
	if err != nil {
		return authzdomain.Grant{}, err
	}
	event, err := s.ledger.Append(ctx, authzdomain.EventGrantCreated, tenantID, actor, authzdomain.GrantCreatedPayload{
		GrantID:  id,
		TenantID: tenantID,
		GroupID:  groupID,
		RoleID:   roleID,
	})
	if err != nil {
		return authzdomain.Grant{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyGrantCreated(event); err != nil {
		return authzdomain.Grant{}, err
	}
	s.writeSnapshotLocked(ctx, id)
	return s.grants[id], nil
}

func (s *Service) applyGroupCreated(event audit.Event) error {
	var payload authzdomain.GroupCreatedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	if err := s.admitGroup(authzdomain.Group{
		ID:       payload.GroupID,
		TenantID: payload.TenantID,
		Name:     payload.Name,
	}); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	s.policyVersion = event.Sequence
	return nil
}

func (s *Service) applyGroupMembership(event audit.Event) error {
	var payload authzdomain.GroupMemberPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	group, exists := s.groups[payload.GroupID]
	if !exists || group.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d names an unknown group", event.Sequence)
	}
	principal, exists := s.principals[payload.PrincipalID]
	if !exists || principal.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d names an unknown principal", event.Sequence)
	}

	members := s.memberships[payload.GroupID]
	_, isMember := members[payload.PrincipalID]
	switch event.Type {
	case authzdomain.EventGroupMemberAdded:
		if isMember {
			return fmt.Errorf("event sequence %d adds a duplicate membership", event.Sequence)
		}
		if members == nil {
			members = make(map[string]struct{})
			s.memberships[payload.GroupID] = members
		}
		members[payload.PrincipalID] = struct{}{}
	case authzdomain.EventGroupMemberRemoved:
		if !isMember {
			return fmt.Errorf("event sequence %d removes an absent membership", event.Sequence)
		}
		delete(members, payload.PrincipalID)
	default:
		return fmt.Errorf("event sequence %d has unexpected type %q", event.Sequence, event.Type)
	}
	s.policyVersion = event.Sequence
	return nil
}

func (s *Service) admitGroup(group authzdomain.Group) error {
	if err := authzdomain.ValidateGroupID(group.ID); err != nil {
		return err
	}
	if err := tenantdomain.ValidateID(group.TenantID); err != nil {
		return err
	}
	if err := tenantdomain.ValidateName(group.Name); err != nil {
		return fmt.Errorf("group name: %w", err)
	}
	if _, exists := s.byID[group.TenantID]; !exists {
		return fmt.Errorf("group %s belongs to unknown tenant", group.ID)
	}
	if _, exists := s.groups[group.ID]; exists {
		return errors.New("duplicate group ID")
	}
	nameKey := identifierKey(group.TenantID, "group", group.Name)
	if _, exists := s.groupNames[nameKey]; exists {
		return fmt.Errorf("group name %q is defined twice", group.Name)
	}
	s.groups[group.ID] = group
	s.groupNames[nameKey] = group.ID
	return nil
}
