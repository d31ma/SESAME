package identity

import (
	"context"
	"errors"
	"fmt"
	"sort"

	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	scimdomain "github.com/d31ma/sesame/internal/domain/scim"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
)

// ErrSCIMGroupNotFound reports an unknown provisioned group.
var ErrSCIMGroupNotFound = errors.New("provisioned group not found")

// ProvisionedGroup is a SCIM view of a SESAME group.
type ProvisionedGroup struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	Members     []string `json:"members"`
}

// requireGroupManagementLocked is the gate `CanManageGroups` exists for.
//
// Group membership drives authorization decisions, so a directory that can
// move people between groups can grant privilege. A client provisioned only
// to create and deactivate people must not be able to do that, and the check
// lives here — one place, applied to every group operation — rather than in
// each handler where one could be forgotten.
// requireGroupManagement is the same gate taken before any parsing happens,
// so a client without the grant gets one consistent answer and learns nothing
// about whether its payload was well-formed. The authoritative check remains
// under the lock, where the state it reads cannot change beneath it.
func (s *Service) requireGroupManagement(client scimdomain.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requireGroupManagementLocked(client)
}

func (s *Service) requireGroupManagementLocked(client scimdomain.Client) error {
	if err := s.checkProvisioningClientLocked(client); err != nil {
		return err
	}
	stored := s.scimClients[client.ID]
	if !stored.Client.CanManageGroups {
		return ErrProvisioningForbidden
	}
	return nil
}

// GroupProvision creates a SESAME group from a SCIM Group payload.
//
// The group is created through the same command an administrator uses, so an
// authorization decision cannot tell whether a group arrived by sync or by
// hand.
func (s *Service) GroupProvision(
	ctx context.Context,
	client scimdomain.Client,
	document []byte,
	actor string,
) (ProvisionedGroup, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return ProvisionedGroup{}, err
	}
	if err := s.requireGroupManagement(client); err != nil {
		return ProvisionedGroup{}, err
	}
	group, err := scimdomain.ParseGroup(document)
	if err != nil {
		return ProvisionedGroup{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireGroupManagementLocked(client); err != nil {
		return ProvisionedGroup{}, err
	}
	return s.createProvisionedGroupLocked(ctx, client, group, actor)
}

func (s *Service) createProvisionedGroupLocked(
	ctx context.Context,
	client scimdomain.Client,
	group scimdomain.Group,
	actor string,
) (ProvisionedGroup, error) {
	created, err := s.groupCreateLocked(ctx, client.TenantID, group.DisplayName, actor)
	if err != nil {
		return ProvisionedGroup{}, err
	}
	// Members named in the create are applied through the same path a PATCH
	// uses, so a member added at creation and one added later are the same
	// event with the same audit shape.
	if err := s.changeMembersLocked(ctx, client, created.ID,
		scimdomain.MembershipChange{Add: memberIDs(group.Members)}, actor); err != nil {
		return ProvisionedGroup{}, err
	}
	s.writeSnapshotLocked(ctx, created.ID)
	return s.provisionedGroupViewLocked(created.ID), nil
}

func memberIDs(members []scimdomain.GroupMember) []string {
	values := make([]string, 0, len(members))
	for _, member := range members {
		if member.Value != "" {
			values = append(values, member.Value)
		}
	}
	return values
}

// GroupGet returns one provisioned group within its client's tenant.
func (s *Service) GroupGet(
	client scimdomain.Client,
	groupID string,
) (ProvisionedGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireGroupManagementLocked(client); err != nil {
		return ProvisionedGroup{}, err
	}
	if err := s.checkProvisionedGroupLocked(client, groupID); err != nil {
		return ProvisionedGroup{}, err
	}
	return s.provisionedGroupViewLocked(groupID), nil
}

// checkProvisionedGroupLocked confirms a group exists inside this tenant.
func (s *Service) checkProvisionedGroupLocked(
	client scimdomain.Client,
	groupID string,
) error {
	group, exists := s.groups[groupID]
	if !exists || group.TenantID != client.TenantID {
		return ErrSCIMGroupNotFound
	}
	return nil
}

// GroupList returns this tenant's groups, bounded by pagination.
type GroupList struct {
	TotalResults int                `json:"totalResults"`
	StartIndex   int                `json:"startIndex"`
	ItemsPerPage int                `json:"itemsPerPage"`
	Resources    []ProvisionedGroup `json:"Resources"`
}

// GroupList answers a paginated read.
func (s *Service) GroupList(
	client scimdomain.Client,
	filterExpression string,
	startIndex, count int,
) (GroupList, error) {
	if err := s.requireGroupManagement(client); err != nil {
		return GroupList{}, err
	}
	filter, filtered, err := scimdomain.ParseFilter(filterExpression)
	if err != nil {
		return GroupList{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireGroupManagementLocked(client); err != nil {
		return GroupList{}, err
	}
	matched := s.matchGroupsLocked(client, filter, filtered)
	return paginateGroups(matched, scimdomain.ResolvePage(startIndex, count)), nil
}

func (s *Service) matchGroupsLocked(
	client scimdomain.Client,
	filter scimdomain.Filter,
	filtered bool,
) []ProvisionedGroup {
	matched := make([]ProvisionedGroup, 0, len(s.groups))
	for groupID, group := range s.groups {
		if group.TenantID != client.TenantID {
			continue
		}
		// displayName is the only filterable group attribute, and it maps
		// onto userName's position in the shared filter grammar.
		if filtered && group.Name != filter.Value {
			continue
		}
		matched = append(matched, s.provisionedGroupViewLocked(groupID))
	}
	sort.Slice(matched, func(left, right int) bool {
		return matched[left].ID < matched[right].ID
	})
	return matched
}

func paginateGroups(matched []ProvisionedGroup, page scimdomain.Page) GroupList {
	total := len(matched)
	start := page.StartIndex - 1
	if start > total {
		start = total
	}
	end := start + page.Count
	if end > total {
		end = total
	}
	window := matched[start:end]
	return GroupList{
		TotalResults: total,
		StartIndex:   page.StartIndex,
		ItemsPerPage: len(window),
		Resources:    window,
	}
}

// GroupPatch applies membership and identity changes to a group.
//
// Every change is resolved before any is applied. A half-applied membership
// PATCH leaves people holding privilege the directory believes it removed.
func (s *Service) GroupPatch(
	ctx context.Context,
	client scimdomain.Client,
	groupID string,
	document []byte,
	actor string,
) (ProvisionedGroup, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return ProvisionedGroup{}, err
	}
	if err := s.requireGroupManagement(client); err != nil {
		return ProvisionedGroup{}, err
	}
	changes, _, err := scimdomain.ParseGroupPatch(document)
	if err != nil {
		return ProvisionedGroup{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireGroupManagementLocked(client); err != nil {
		return ProvisionedGroup{}, err
	}
	if err := s.checkProvisionedGroupLocked(client, groupID); err != nil {
		return ProvisionedGroup{}, err
	}
	return s.writeGroupChangesLocked(ctx, client, groupID, changes, actor)
}

func (s *Service) writeGroupChangesLocked(
	ctx context.Context,
	client scimdomain.Client,
	groupID string,
	changes []scimdomain.MembershipChange,
	actor string,
) (ProvisionedGroup, error) {
	for _, change := range changes {
		if err := s.changeMembersLocked(ctx, client, groupID, change, actor); err != nil {
			return ProvisionedGroup{}, err
		}
	}
	s.writeSnapshotLocked(ctx, groupID)
	return s.provisionedGroupViewLocked(groupID), nil
}

// changeMembersLocked applies one resolved change.
func (s *Service) changeMembersLocked(
	ctx context.Context,
	client scimdomain.Client,
	groupID string,
	change scimdomain.MembershipChange,
	actor string,
) error {
	if change.Replace {
		if err := s.clearMembersLocked(ctx, client, groupID, change.Add, actor); err != nil {
			return err
		}
	}
	for _, principalID := range change.Remove {
		if err := s.setMembershipLocked(ctx, client, groupID, principalID, false, actor); err != nil {
			return err
		}
	}
	for _, principalID := range change.Add {
		if err := s.setMembershipLocked(ctx, client, groupID, principalID, true, actor); err != nil {
			return err
		}
	}
	return nil
}

// clearMembersLocked removes everyone a replace does not keep.
func (s *Service) clearMembersLocked(
	ctx context.Context,
	client scimdomain.Client,
	groupID string,
	keeping []string,
	actor string,
) error {
	keep := make(map[string]struct{}, len(keeping))
	for _, principalID := range keeping {
		keep[principalID] = struct{}{}
	}
	for _, principalID := range s.groupMembersLocked(groupID) {
		if _, kept := keep[principalID]; kept {
			continue
		}
		if err := s.setMembershipLocked(ctx, client, groupID, principalID, false, actor); err != nil {
			return err
		}
	}
	return nil
}

// setMembershipLocked adds or removes one principal, refusing a principal
// outside this tenant.
//
// A directory that could name any principal identifier could add somebody
// else's user to a group that carries a role here, so the tenant check is not
// optional even though the group itself was already checked.
func (s *Service) setMembershipLocked(
	ctx context.Context,
	client scimdomain.Client,
	groupID, principalID string,
	member bool,
	actor string,
) error {
	principal, exists := s.principals[principalID]
	if !exists || principal.TenantID != client.TenantID {
		return fmt.Errorf("%w: %s", ErrPrincipalNotFound, principalID)
	}
	// A membership change that changes nothing appends nothing. Directories
	// reconcile by re-sending the whole desired state, so the common case is
	// an add for somebody already in the group — and the projection rejects a
	// duplicate, which would make every unchanged re-sync fail.
	_, alreadyMember := s.memberships[groupID][principalID]
	if alreadyMember == member {
		return nil
	}
	eventType := authzdomain.EventGroupMemberRemoved
	if member {
		eventType = authzdomain.EventGroupMemberAdded
	}
	event, err := s.ledger.Append(ctx, eventType, client.TenantID, actor,
		authzdomain.GroupMemberPayload{
			GroupID:     groupID,
			TenantID:    client.TenantID,
			PrincipalID: principalID,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applyGroupMembership(event)
}

// groupMembersLocked lists a group's current members, sorted so a replace
// applies deterministically.
func (s *Service) groupMembersLocked(groupID string) []string {
	members := make([]string, 0, len(s.memberships[groupID]))
	for principalID := range s.memberships[groupID] {
		members = append(members, principalID)
	}
	sort.Strings(members)
	return members
}

func (s *Service) provisionedGroupViewLocked(groupID string) ProvisionedGroup {
	return ProvisionedGroup{
		ID:          groupID,
		DisplayName: s.groups[groupID].Name,
		Members:     s.groupMembersLocked(groupID),
	}
}

// GroupDeprovision empties a group rather than deleting it.
//
// Deleting would remove the subject of every grant and audit record naming
// it. Emptying achieves what a directory means — nobody holds this group's
// privilege any more — while leaving the group and its grants readable, so an
// operator can see what access was removed and reinstate it deliberately.
func (s *Service) GroupDeprovision(
	ctx context.Context,
	client scimdomain.Client,
	groupID, actor string,
) error {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireGroupManagementLocked(client); err != nil {
		return err
	}
	if err := s.checkProvisionedGroupLocked(client, groupID); err != nil {
		return err
	}
	if err := s.clearMembersLocked(ctx, client, groupID, nil, actor); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, groupID)
	return nil
}

// groupCreateLocked creates a group without re-taking the lock, so
// provisioning uses the same validation and event as the administrative path.
func (s *Service) groupCreateLocked(
	ctx context.Context,
	tenantID, name, actor string,
) (authzdomain.Group, error) {
	normalized := tenantdomain.NormalizeName(name)
	if existing, claimed := s.groupNames[identifierKey(tenantID, "group", normalized)]; claimed {
		return s.groups[existing], nil
	}
	groupID, err := authzdomain.NewGroupID()
	if err != nil {
		return authzdomain.Group{}, err
	}
	event, err := s.ledger.Append(ctx, authzdomain.EventGroupCreated, tenantID, actor,
		authzdomain.GroupCreatedPayload{
			GroupID:  groupID,
			TenantID: tenantID,
			Name:     normalized,
		})
	if err != nil {
		return authzdomain.Group{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyGroupCreated(event); err != nil {
		return authzdomain.Group{}, err
	}
	return s.groups[groupID], nil
}
