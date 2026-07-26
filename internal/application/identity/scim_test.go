package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	scimdomain "github.com/d31ma/sesame/internal/domain/scim"
)

type scimFixture struct {
	service  *Service
	tenantID string
	client   scimdomain.Client
	token    string
}

func newSCIMFixture(t *testing.T) *scimFixture {
	t.Helper()

	service, _, tenantID := bootstrapService(t)
	client, token, err := service.ProvisioningClientRegister(context.Background(),
		tenantID, "Okta production", "", false, "test")
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}
	return &scimFixture{service: service, tenantID: tenantID, client: client, token: token}
}

func scimUserPayload(t *testing.T, overrides map[string]any) []byte {
	t.Helper()

	document := map[string]any{
		"schemas":  []string{scimdomain.SchemaUser},
		"userName": "person@example.com",
	}
	for name, value := range overrides {
		if value == nil {
			delete(document, name)
			continue
		}
		document[name] = value
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestProvisioningCreatesAPrincipal(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	user, err := fixture.service.UserProvision(ctx, fixture.client,
		scimUserPayload(t, map[string]any{"externalId": "okta-00u1"}), "test")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}
	if !user.Active || user.ExternalID != "okta-00u1" {
		t.Fatalf("provisioned %#v", user)
	}
	// The principal is a real one: its identifier is claimed, so a later
	// claim of the same address must conflict.
	_, err = fixture.service.PrincipalCreate(ctx, fixture.tenantID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "person@example.com"}, "test")
	if !errors.Is(err, ErrIdentifierConflict) {
		t.Fatalf("the provisioned identifier was not claimed: %v", err)
	}
}

// TestProvisioningCannotTakeOverAnExistingAccount: POST is a create. Merging
// it into an existing principal would let a provisioning client capture an
// account somebody already has.
func TestProvisioningCannotTakeOverAnExistingAccount(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	if _, err := fixture.service.PrincipalCreate(ctx, fixture.tenantID,
		principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "person@example.com"},
		"test"); err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	_, err := fixture.service.UserProvision(ctx, fixture.client, scimUserPayload(t, nil), "test")
	if !errors.Is(err, ErrSCIMUserConflict) {
		t.Fatalf("error = %v, want ErrSCIMUserConflict", err)
	}
}

// TestProvisioningAnInactiveUserNeverActivatesIt: a principal that is active
// for even a moment is a window nobody asked for.
func TestProvisioningAnInactiveUserNeverActivatesIt(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)

	user, err := fixture.service.UserProvision(context.Background(), fixture.client,
		scimUserPayload(t, map[string]any{"active": false}), "test")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}
	if user.Active {
		t.Fatal("a user provisioned as inactive came back active")
	}
	if fixture.service.principals[user.ID].Status == principaldomain.StatusActive {
		t.Fatal("the principal behind an inactive user is active")
	}
}

// TestDeprovisioningSuspendsRatherThanDeletes protects the audit trail: an
// erased principal would leave every record that names it dangling.
func TestDeprovisioningSuspendsRatherThanDeletes(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	user, err := fixture.service.UserProvision(ctx, fixture.client, scimUserPayload(t, nil), "test")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}
	if err := fixture.service.UserDeprovision(ctx, fixture.client, user.ID, "test"); err != nil {
		t.Fatalf("UserDeprovision() error = %v", err)
	}
	// Idempotent.
	if err := fixture.service.UserDeprovision(ctx, fixture.client, user.ID, "test"); err != nil {
		t.Fatalf("a second UserDeprovision() error = %v", err)
	}

	// The principal still exists and is readable — suspended, not gone.
	after, err := fixture.service.UserGet(fixture.client, user.ID)
	if err != nil {
		t.Fatalf("UserGet() after deprovision error = %v", err)
	}
	if after.Active {
		t.Fatal("a deprovisioned user is still active")
	}
	if _, exists := fixture.service.principals[user.ID]; !exists {
		t.Fatal("deprovisioning deleted the principal")
	}
}

// TestPatchDeactivatesButNeverReactivates: a provider setting active:true on
// a principal an administrator suspended would undo a human decision with a
// directory sync.
func TestPatchDeactivatesButNeverReactivates(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	user, err := fixture.service.UserProvision(ctx, fixture.client, scimUserPayload(t, nil), "test")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}
	patched, err := fixture.service.UserPatch(ctx, fixture.client, user.ID,
		patchPayload(t, "active", false), "test")
	if err != nil {
		t.Fatalf("UserPatch() error = %v", err)
	}
	if patched.Active {
		t.Fatal("active:false did not deactivate")
	}

	reactivated, err := fixture.service.UserPatch(ctx, fixture.client, user.ID,
		patchPayload(t, "active", true), "test")
	if err != nil {
		t.Fatalf("UserPatch() error = %v", err)
	}
	if reactivated.Active {
		t.Fatal("a provisioning client reactivated a suspended principal")
	}
}

func patchPayload(t *testing.T, path string, value any) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]any{
		"schemas": []string{scimdomain.SchemaPatch},
		"Operations": []map[string]any{
			{"op": "replace", "path": path, "value": value},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestDisabledClientStopsProvisioningImmediately: the client is re-read from
// state on every operation, so a token authenticated a moment ago cannot act
// after the client was disabled.
func TestDisabledClientStopsProvisioningImmediately(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	if err := fixture.service.ProvisioningClientDisable(ctx, fixture.tenantID,
		fixture.client.ID, "rotated out", "test"); err != nil {
		t.Fatalf("ProvisioningClientDisable() error = %v", err)
	}
	if _, err := fixture.service.UserProvision(ctx, fixture.client,
		scimUserPayload(t, nil), "test"); !errors.Is(err, ErrProvisioningClientNotFound) {
		t.Fatalf("a disabled client provisioned: %v", err)
	}
	// And its token no longer authenticates.
	if _, err := fixture.service.ProvisioningAuthenticate(fixture.token); !errors.Is(
		err, ErrProvisioningDenied) {
		t.Fatalf("a disabled client's token still authenticates: %v", err)
	}
}

func TestProvisioningAuthenticate(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)

	client, err := fixture.service.ProvisioningAuthenticate(fixture.token)
	if err != nil {
		t.Fatalf("ProvisioningAuthenticate() error = %v", err)
	}
	if client.ID != fixture.client.ID {
		t.Fatalf("authenticated %q, want %q", client.ID, fixture.client.ID)
	}
	for _, bad := range []string{"", "a-forged-token", fixture.token + "x"} {
		if _, err := fixture.service.ProvisioningAuthenticate(bad); !errors.Is(
			err, ErrProvisioningDenied) {
			t.Fatalf("ProvisioningAuthenticate(%q) error = %v", bad, err)
		}
	}
}

// TestProvisioningIsTenantScoped: one tenant's provisioning client must not
// see or touch another tenant's users.
func TestProvisioningIsTenantScoped(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	user, err := fixture.service.UserProvision(ctx, fixture.client, scimUserPayload(t, nil), "test")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}

	other, err := fixture.service.Bootstrap(ctx, "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	intruder, _, err := fixture.service.ProvisioningClientRegister(ctx, other.Tenant.ID,
		"other directory", "", false, "test")
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}

	if _, err := fixture.service.UserGet(intruder, user.ID); !errors.Is(err, ErrSCIMUserNotFound) {
		t.Fatalf("one tenant read another's provisioned user: %v", err)
	}
	if err := fixture.service.UserDeprovision(ctx, intruder, user.ID, "test"); !errors.Is(
		err, ErrSCIMUserNotFound) {
		t.Fatalf("one tenant deprovisioned another's user: %v", err)
	}
	listed, err := fixture.service.UserList(intruder, "", 1, 50)
	if err != nil {
		t.Fatalf("UserList() error = %v", err)
	}
	if listed.TotalResults != 0 {
		t.Fatalf("another tenant's list returned %d users", listed.TotalResults)
	}
}

// TestUserListFiltersAndPaginates covers the read path a reconcile drives.
func TestUserListFiltersAndPaginates(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	for _, name := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if _, err := fixture.service.UserProvision(ctx, fixture.client,
			scimUserPayload(t, map[string]any{"userName": name}), "test"); err != nil {
			t.Fatalf("UserProvision(%s) error = %v", name, err)
		}
	}

	all, err := fixture.service.UserList(fixture.client, "", 1, 50)
	if err != nil {
		t.Fatalf("UserList() error = %v", err)
	}
	if all.TotalResults != 3 {
		t.Fatalf("total = %d, want 3", all.TotalResults)
	}

	filtered, err := fixture.service.UserList(fixture.client, `userName eq "b@example.com"`, 1, 50)
	if err != nil {
		t.Fatalf("UserList() filtered error = %v", err)
	}
	if filtered.TotalResults != 1 || filtered.Resources[0].UserName != "b@example.com" {
		t.Fatalf("filtered %#v", filtered)
	}

	// SCIM counts from 1, and totalResults reports the whole match, not the
	// page — a reconcile uses it to decide whether to ask for more.
	page, err := fixture.service.UserList(fixture.client, "", 2, 1)
	if err != nil {
		t.Fatalf("UserList() paged error = %v", err)
	}
	if page.TotalResults != 3 || page.ItemsPerPage != 1 || page.StartIndex != 2 {
		t.Fatalf("page %#v", page)
	}
	if page.Resources[0].ID == all.Resources[0].ID {
		t.Fatal("startIndex 2 returned the first user")
	}

	// A window past the end is empty, not an error and not a panic.
	beyond, err := fixture.service.UserList(fixture.client, "", 99, 10)
	if err != nil {
		t.Fatalf("UserList() beyond the end error = %v", err)
	}
	if len(beyond.Resources) != 0 || beyond.TotalResults != 3 {
		t.Fatalf("beyond %#v", beyond)
	}
}

// TestProvisioningSurvivesSnapshotRestore is the projection regression: token
// digests must travel or every provisioning client silently stops
// authenticating after a restart.
func TestProvisioningSurvivesSnapshotRestore(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	if _, err := fixture.service.UserProvision(ctx, fixture.client,
		scimUserPayload(t, nil), "test"); err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}

	fixture.service.mu.Lock()
	state := fixture.service.exportStateLocked()
	fixture.service.mu.Unlock()

	if len(state.SCIMClients) != 1 || state.SCIMClients[0].TokenDigest == "" {
		t.Fatalf("the snapshot carries %#v", state.SCIMClients)
	}
	if len(state.SCIMUsers) != 1 {
		t.Fatalf("the snapshot carries %d provisioned users", len(state.SCIMUsers))
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	// The token itself must never appear; only its digest.
	if strings.Contains(string(encoded), fixture.token) {
		t.Fatal("a provisioning token appears in the serialised snapshot")
	}
}

// TestPatchRefusesNonStringValues: a replacement value of the wrong JSON type
// must be refused, not coerced. Coercing `userName: 42` into "42" would
// rename someone to a number.
func TestPatchRefusesNonStringValues(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	user, err := fixture.service.UserProvision(ctx, fixture.client, scimUserPayload(t, nil), "test")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}
	for name, value := range map[string]any{
		"number":  42,
		"boolean": true,
		"object":  map[string]any{"givenName": "A"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.service.UserPatch(ctx, fixture.client, user.ID,
				patchPayload(t, "userName", value), "test"); err == nil {
				t.Fatalf("UserPatch coerced a %s into a userName", name)
			}
		})
	}

	// A userName that would not survive validation on create must not survive
	// a patch either.
	if _, err := fixture.service.UserPatch(ctx, fixture.client, user.ID,
		patchPayload(t, "userName", " padded@example.com "), "test"); err == nil {
		t.Fatal("UserPatch accepted a padded userName")
	}

	// The valid path still works, and displayName and externalId are settable.
	patched, err := fixture.service.UserPatch(ctx, fixture.client, user.ID,
		patchPayload(t, "displayName", "A Person"), "test")
	if err != nil {
		t.Fatalf("UserPatch() error = %v", err)
	}
	if patched.DisplayName != "A Person" {
		t.Fatalf("displayName = %q", patched.DisplayName)
	}
	if _, err := fixture.service.UserPatch(ctx, fixture.client, user.ID,
		patchPayload(t, "externalId", "okta-00u9"), "test"); err != nil {
		t.Fatalf("UserPatch(externalId) error = %v", err)
	}
}

// TestRotatingAProvisioningTokenInvalidatesTheOldOne: an overlap window is
// exactly what an attacker holding the leaked token would use.
func TestRotatingAProvisioningTokenInvalidatesTheOldOne(t *testing.T) {
	t.Parallel()

	fixture := newSCIMFixture(t)
	ctx := context.Background()

	replacement, err := fixture.service.ProvisioningClientRotateToken(ctx,
		fixture.tenantID, fixture.client.ID, "test")
	if err != nil {
		t.Fatalf("ProvisioningClientRotateToken() error = %v", err)
	}
	if replacement == fixture.token {
		t.Fatal("rotation returned the same token")
	}
	if _, err := fixture.service.ProvisioningAuthenticate(fixture.token); !errors.Is(
		err, ErrProvisioningDenied) {
		t.Fatalf("the old token still authenticates: %v", err)
	}
	client, err := fixture.service.ProvisioningAuthenticate(replacement)
	if err != nil {
		t.Fatalf("the replacement token does not authenticate: %v", err)
	}
	if client.ID != fixture.client.ID {
		t.Fatalf("rotation moved the client identity to %q", client.ID)
	}

	// Cross-tenant and disabled clients cannot be rotated.
	other, err := fixture.service.Bootstrap(ctx, "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if _, err := fixture.service.ProvisioningClientRotateToken(ctx, other.Tenant.ID,
		fixture.client.ID, "test"); !errors.Is(err, ErrProvisioningClientNotFound) {
		t.Fatalf("one tenant rotated another's token: %v", err)
	}
	if err := fixture.service.ProvisioningClientDisable(ctx, fixture.tenantID,
		fixture.client.ID, "", "test"); err != nil {
		t.Fatalf("ProvisioningClientDisable() error = %v", err)
	}
	if _, err := fixture.service.ProvisioningClientRotateToken(ctx, fixture.tenantID,
		fixture.client.ID, "test"); !errors.Is(err, ErrProvisioningClientNotFound) {
		t.Fatalf("a disabled client's token was rotated: %v", err)
	}
}
