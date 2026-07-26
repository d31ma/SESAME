package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	scimdomain "github.com/d31ma/sesame/internal/domain/scim"
)

// groupFixture is a provisioning client that may manage groups, plus two
// provisioned users to move around.
type groupFixture struct {
	*scimFixture
	first  string
	second string
}

func newGroupFixture(t *testing.T, canManageGroups bool) *groupFixture {
	t.Helper()

	service, _, tenantID := bootstrapService(t)
	client, token, err := service.ProvisioningClientRegister(context.Background(),
		tenantID, "Okta production", "", canManageGroups, "test")
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}
	fixture := &groupFixture{scimFixture: &scimFixture{
		service: service, tenantID: tenantID, client: client, token: token,
	}}
	ctx := context.Background()
	for _, userName := range []string{"first@example.com", "second@example.com"} {
		user, err := service.UserProvision(ctx, client,
			scimUserPayload(t, map[string]any{"userName": userName}), "test")
		if err != nil {
			t.Fatalf("UserProvision(%s) error = %v", userName, err)
		}
		if fixture.first == "" {
			fixture.first = user.ID
		} else {
			fixture.second = user.ID
		}
	}
	return fixture
}

func groupPayload(t *testing.T, displayName string, members ...string) []byte {
	t.Helper()

	entries := make([]map[string]any, 0, len(members))
	for _, member := range members {
		entries = append(entries, map[string]any{"value": member})
	}
	raw, err := json.Marshal(map[string]any{
		"schemas":     []string{scimdomain.SchemaGroup},
		"displayName": displayName,
		"members":     entries,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestGroupManagementRequiresTheGrant is what CanManageGroups exists for.
// Group membership drives authorization decisions, so a directory that can
// change it can grant privilege.
func TestGroupManagementRequiresTheGrant(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, false)
	ctx := context.Background()

	_, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering"), "test")
	if !errors.Is(err, ErrProvisioningForbidden) {
		t.Fatalf("GroupProvision() error = %v, want ErrProvisioningForbidden", err)
	}

	// Every group operation is gated, not just the create.
	for name, call := range map[string]func() error{
		"get": func() error {
			_, err := fixture.service.GroupGet(fixture.client, "grp_x")
			return err
		},
		"list": func() error {
			_, err := fixture.service.GroupList(fixture.client, "", 1, 50)
			return err
		},
		"patch": func() error {
			_, err := fixture.service.GroupPatch(ctx, fixture.client, "grp_x",
				groupPatch(t, "add", "members", fixture.first), "test")
			return err
		},
		"deprovision": func() error {
			return fixture.service.GroupDeprovision(ctx, fixture.client, "grp_x", "test")
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrProvisioningForbidden) {
				t.Fatalf("%s error = %v, want ErrProvisioningForbidden", name, err)
			}
		})
	}
}

func groupPatch(t *testing.T, op, path string, members ...string) []byte {
	t.Helper()

	operation := map[string]any{"op": op, "path": path}
	if members != nil {
		entries := make([]map[string]any, 0, len(members))
		for _, member := range members {
			entries = append(entries, map[string]any{"value": member})
		}
		operation["value"] = entries
	}
	raw, err := json.Marshal(map[string]any{
		"schemas":    []string{scimdomain.SchemaPatch},
		"Operations": []map[string]any{operation},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestGroupProvisioningDrivesAuthorization is the point of the whole slice: a
// synced group has to behave like an administrator's group, or the sync is
// decorative.
func TestGroupProvisioningDrivesAuthorization(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, true)
	ctx := context.Background()

	group, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering", fixture.first), "test")
	if err != nil {
		t.Fatalf("GroupProvision() error = %v", err)
	}
	if len(group.Members) != 1 || group.Members[0] != fixture.first {
		t.Fatalf("provisioned %#v", group)
	}

	// The group is a real SESAME group: the administrative lookup finds it.
	found, err := fixture.service.GroupGetByName(fixture.tenantID, "engineering")
	if err != nil {
		t.Fatalf("GroupGetByName() error = %v", err)
	}
	if found.ID != group.ID {
		t.Fatalf("the provisioned group is not the administrative one: %q vs %q",
			found.ID, group.ID)
	}
}

// TestGroupPatchSupportsBothRemovalDialects: directories disagree about how
// to express member removal, and a service provider that supports one form
// does not work with half the market.
func TestGroupPatchSupportsBothRemovalDialects(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, true)
	ctx := context.Background()

	group, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering", fixture.first, fixture.second), "test")
	if err != nil {
		t.Fatalf("GroupProvision() error = %v", err)
	}
	if len(group.Members) != 2 {
		t.Fatalf("provisioned with %d members", len(group.Members))
	}

	// Dialect one: remove with a value list.
	after, err := fixture.service.GroupPatch(ctx, fixture.client, group.ID,
		groupPatch(t, "remove", "members", fixture.first), "test")
	if err != nil {
		t.Fatalf("GroupPatch(remove list) error = %v", err)
	}
	if len(after.Members) != 1 || after.Members[0] != fixture.second {
		t.Fatalf("after removing the first member: %#v", after)
	}

	// Dialect two: remove through a value path.
	valuePath := `members[value eq "` + fixture.second + `"]`
	after, err = fixture.service.GroupPatch(ctx, fixture.client, group.ID,
		groupPatch(t, "remove", valuePath), "test")
	if err != nil {
		t.Fatalf("GroupPatch(remove value path) error = %v", err)
	}
	if len(after.Members) != 0 {
		t.Fatalf("after removing the second member: %#v", after)
	}
}

// TestGroupPatchReplaceEmptiesWhatItOmits: a replace is the destructive one,
// and it has to actually remove the members it leaves out.
func TestGroupPatchReplaceEmptiesWhatItOmits(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, true)
	ctx := context.Background()

	group, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering", fixture.first, fixture.second), "test")
	if err != nil {
		t.Fatalf("GroupProvision() error = %v", err)
	}
	after, err := fixture.service.GroupPatch(ctx, fixture.client, group.ID,
		groupPatch(t, "replace", "members", fixture.second), "test")
	if err != nil {
		t.Fatalf("GroupPatch(replace) error = %v", err)
	}
	if len(after.Members) != 1 || after.Members[0] != fixture.second {
		t.Fatalf("after replace: %#v", after)
	}
}

// TestGroupMembershipCannotCrossTenants is the escalation this surface would
// otherwise allow: name any principal identifier and put it in a group that
// carries a role here.
func TestGroupMembershipCannotCrossTenants(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, true)
	ctx := context.Background()

	other, err := fixture.service.Bootstrap(ctx, "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	outsiderClient, _, err := fixture.service.ProvisioningClientRegister(ctx,
		other.Tenant.ID, "other directory", "", true, "test")
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}
	outsider, err := fixture.service.UserProvision(ctx, outsiderClient,
		scimUserPayload(t, map[string]any{"userName": "outsider@example.com"}), "test")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}

	group, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering"), "test")
	if err != nil {
		t.Fatalf("GroupProvision() error = %v", err)
	}
	if _, err := fixture.service.GroupPatch(ctx, fixture.client, group.ID,
		groupPatch(t, "add", "members", outsider.ID), "test"); !errors.Is(
		err, ErrPrincipalNotFound) {
		t.Fatalf("another tenant's principal joined this group: %v", err)
	}
	if _, err := fixture.service.GroupGet(outsiderClient, group.ID); !errors.Is(
		err, ErrSCIMGroupNotFound) {
		t.Fatalf("another tenant read this group: %v", err)
	}
}

// TestGroupDeprovisionEmptiesRatherThanDeletes keeps the group and its grants
// readable, so an operator can see what access was removed.
func TestGroupDeprovisionEmptiesRatherThanDeletes(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, true)
	ctx := context.Background()

	group, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering", fixture.first, fixture.second), "test")
	if err != nil {
		t.Fatalf("GroupProvision() error = %v", err)
	}
	if err := fixture.service.GroupDeprovision(ctx, fixture.client, group.ID, "test"); err != nil {
		t.Fatalf("GroupDeprovision() error = %v", err)
	}
	after, err := fixture.service.GroupGet(fixture.client, group.ID)
	if err != nil {
		t.Fatalf("a deprovisioned group is unreadable: %v", err)
	}
	if len(after.Members) != 0 {
		t.Fatalf("a deprovisioned group still has %d members", len(after.Members))
	}
	if _, err := fixture.service.GroupGetByName(fixture.tenantID, "engineering"); err != nil {
		t.Fatalf("deprovisioning deleted the group: %v", err)
	}
}

// TestGroupProvisionIsIdempotentOnName: a directory re-syncing must not
// create a second group with the same name, because two groups named alike
// is a privilege confusion an operator cannot see.
func TestGroupProvisionIsIdempotentOnName(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, true)
	ctx := context.Background()

	first, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering", fixture.first), "test")
	if err != nil {
		t.Fatalf("GroupProvision() error = %v", err)
	}
	second, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering", fixture.second), "test")
	if err != nil {
		t.Fatalf("a re-sync failed: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("a re-sync created a second group: %q then %q", first.ID, second.ID)
	}
}

// TestGroupPayloadsAreBounded covers the untrusted-input edge.
func TestGroupPayloadsAreBounded(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, true)
	ctx := context.Background()

	for name, body := range map[string][]byte{
		"wrong schema":   scimUserPayload(t, nil),
		"no displayName": groupPayload(t, ""),
		"padded name":    groupPayload(t, " engineering "),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.service.GroupProvision(ctx, fixture.client,
				body, "test"); err == nil {
				t.Fatalf("GroupProvision accepted a %s payload", name)
			}
		})
	}

	// An unsupported PATCH path is refused rather than ignored.
	group, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering"), "test")
	if err != nil {
		t.Fatalf("GroupProvision() error = %v", err)
	}
	for name, body := range map[string][]byte{
		"unknown path":      groupPatch(t, "replace", "externalId", fixture.first),
		"add on a filter":   groupPatch(t, "add", `members[value eq "`+fixture.first+`"]`),
		"unknown operation": groupPatch(t, "increment", "members", fixture.first),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.service.GroupPatch(ctx, fixture.client, group.ID,
				body, "test"); err == nil {
				t.Fatalf("GroupPatch accepted %s", name)
			}
		})
	}
}

// TestGroupResyncIsIdempotent: a directory reconciles by re-sending the whole
// desired state, so the common case is an add for somebody already in the
// group. If that errored, every unchanged re-sync would fail.
func TestGroupResyncIsIdempotent(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, true)
	ctx := context.Background()

	group, err := fixture.service.GroupProvision(ctx, fixture.client,
		groupPayload(t, "engineering", fixture.first), "test")
	if err != nil {
		t.Fatalf("GroupProvision() error = %v", err)
	}
	for attempt := range 3 {
		after, err := fixture.service.GroupPatch(ctx, fixture.client, group.ID,
			groupPatch(t, "add", "members", fixture.first), "test")
		if err != nil {
			t.Fatalf("re-sync %d failed: %v", attempt, err)
		}
		if len(after.Members) != 1 {
			t.Fatalf("re-sync %d left %d members", attempt, len(after.Members))
		}
	}
	// Removing somebody who is not a member is equally a no-op.
	after, err := fixture.service.GroupPatch(ctx, fixture.client, group.ID,
		groupPatch(t, "remove", "members", fixture.second), "test")
	if err != nil {
		t.Fatalf("removing a non-member failed: %v", err)
	}
	if len(after.Members) != 1 {
		t.Fatalf("removing a non-member changed the group: %#v", after)
	}
}

// TestGroupListFiltersAndPaginates covers the read a reconcile drives.
func TestGroupListFiltersAndPaginates(t *testing.T) {
	t.Parallel()

	fixture := newGroupFixture(t, true)
	ctx := context.Background()

	for _, name := range []string{"engineering", "finance", "support"} {
		if _, err := fixture.service.GroupProvision(ctx, fixture.client,
			groupPayload(t, name, fixture.first), "test"); err != nil {
			t.Fatalf("GroupProvision(%s) error = %v", name, err)
		}
	}

	all, err := fixture.service.GroupList(fixture.client, "", 1, 50)
	if err != nil {
		t.Fatalf("GroupList() error = %v", err)
	}
	if all.TotalResults != 3 {
		t.Fatalf("total = %d, want 3", all.TotalResults)
	}

	filtered, err := fixture.service.GroupList(fixture.client, `displayName eq "finance"`, 1, 50)
	if err != nil {
		t.Fatalf("GroupList() filtered error = %v", err)
	}
	if filtered.TotalResults != 1 || filtered.Resources[0].DisplayName != "finance" {
		t.Fatalf("filtered %#v", filtered)
	}

	// SCIM counts from 1, and totalResults reports the whole match.
	page, err := fixture.service.GroupList(fixture.client, "", 2, 1)
	if err != nil {
		t.Fatalf("GroupList() paged error = %v", err)
	}
	if page.TotalResults != 3 || page.ItemsPerPage != 1 || page.StartIndex != 2 {
		t.Fatalf("page %#v", page)
	}

	// A window past the end is empty, not an error and not a panic.
	beyond, err := fixture.service.GroupList(fixture.client, "", 99, 10)
	if err != nil {
		t.Fatalf("GroupList() beyond the end error = %v", err)
	}
	if len(beyond.Resources) != 0 || beyond.TotalResults != 3 {
		t.Fatalf("beyond %#v", beyond)
	}

	// Another tenant's directory sees none of them.
	other, err := fixture.service.Bootstrap(ctx, "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	intruder, _, err := fixture.service.ProvisioningClientRegister(ctx, other.Tenant.ID,
		"other directory", "", true, "test")
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}
	isolated, err := fixture.service.GroupList(intruder, "", 1, 50)
	if err != nil {
		t.Fatalf("GroupList() error = %v", err)
	}
	if isolated.TotalResults != 0 {
		t.Fatalf("another tenant's directory saw %d groups", isolated.TotalResults)
	}
}
