package fylo_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	scimdomain "github.com/d31ma/sesame/internal/domain/scim"
)

// TestRealFYLOProvisioningSurvivesRestart proves against a real FYLO runtime
// that provisioning state is durable.
//
// Three things are at stake and each fails differently. A token digest that
// does not replay means every directory silently stops authenticating after a
// restart — and a directory that cannot authenticate deactivates nobody, so a
// departed employee keeps their access. A provisioning record that does not
// replay means a reconcile sees no users and re-creates all of them,
// duplicating every account. And a deprovisioned user must come back
// deprovisioned: suspension is the security decision, and a restart that
// forgets it is a restart that reinstates somebody.
func TestRealFYLOProvisioningSurvivesRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}
	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	root, err := os.MkdirTemp("", "sesame-scim-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	now := time.Unix(1_700_000_000, 0).UTC()

	open := func() (*fyloadapter.Client, *identityapp.Service) {
		t.Helper()
		client, err := fyloadapter.Start(ctx, config)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		ledger, events, err := securityledger.Open(ctx, client)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		service, err := identityapp.New(ledger, events)
		if err != nil {
			t.Fatalf("identity.New() error = %v", err)
		}
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	provisioner, token, err := service.ProvisioningClientRegister(ctx, tenant.Tenant.ID,
		"Okta production", "", false, "test:integration")
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}

	// One user stays active; a second is deprovisioned, so the restart has
	// both states to replay.
	active, err := service.UserProvision(ctx, provisioner,
		scimPayload(t, "stays@example.com"), "test:integration")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}
	departed, err := service.UserProvision(ctx, provisioner,
		scimPayload(t, "departed@example.com"), "test:integration")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}
	if err := service.UserDeprovision(ctx, provisioner, departed.ID, "test:integration"); err != nil {
		t.Fatalf("UserDeprovision() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// ---- restart ----
	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	// The token digest replays, so the directory can still authenticate.
	// Without this a departed employee keeps their access, because a
	// directory that cannot authenticate deactivates nobody.
	recovered, err := replayed.ProvisioningAuthenticate(token)
	if err != nil {
		t.Fatalf("the provisioning token does not authenticate after restart: %v", err)
	}
	if recovered.ID != provisioner.ID {
		t.Fatalf("the token resolved to %q, want %q", recovered.ID, provisioner.ID)
	}
	if recovered.IdentifierNamespace != scimdomain.DefaultIdentifierNamespace {
		t.Fatalf("identifier namespace after restart = %q", recovered.IdentifierNamespace)
	}

	// Both provisioning records replay, with their statuses intact.
	listed, err := replayed.UserList(recovered, "", 1, 50)
	if err != nil {
		t.Fatalf("UserList() after restart error = %v", err)
	}
	if listed.TotalResults != 2 {
		t.Fatalf("after restart the directory sees %d users, want 2", listed.TotalResults)
	}
	stillActive, err := replayed.UserGet(recovered, active.ID)
	if err != nil {
		t.Fatalf("UserGet() after restart error = %v", err)
	}
	if !stillActive.Active {
		t.Fatal("an active user came back deactivated")
	}
	stillGone, err := replayed.UserGet(recovered, departed.ID)
	if err != nil {
		t.Fatalf("UserGet() after restart error = %v", err)
	}
	if stillGone.Active {
		t.Fatal("a deprovisioned user was reinstated by a restart")
	}

	// A reconcile finds the existing user rather than re-creating it, which
	// is what stops a restart from duplicating every account.
	if _, err := replayed.UserProvision(ctx, recovered,
		scimPayload(t, "stays@example.com"), "test:integration"); !errors.Is(
		err, identityapp.ErrSCIMUserConflict) {
		t.Fatalf("a reconcile after restart re-created an existing user: %v", err)
	}

	// Rotation still works across the restart, and retires the old token.
	replacement, err := replayed.ProvisioningClientRotateToken(ctx, tenant.Tenant.ID,
		provisioner.ID, "test:integration")
	if err != nil {
		t.Fatalf("ProvisioningClientRotateToken() after restart error = %v", err)
	}
	if _, err := replayed.ProvisioningAuthenticate(token); !errors.Is(
		err, identityapp.ErrProvisioningDenied) {
		t.Fatalf("the retired token still authenticates: %v", err)
	}
	if _, err := replayed.ProvisioningAuthenticate(replacement); err != nil {
		t.Fatalf("the replacement token does not authenticate: %v", err)
	}

	// The provisioned principals are real: their identifiers stayed claimed.
	if _, err := replayed.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "stays@example.com"},
		"test:integration"); !errors.Is(err, identityapp.ErrIdentifierConflict) {
		t.Fatalf("a provisioned identifier was released by the restart: %v", err)
	}
}

func scimPayload(t *testing.T, userName string) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]any{
		"schemas":  []string{scimdomain.SchemaUser},
		"userName": userName,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestRealFYLOProvisionedGroupsSurviveRestart proves against a real FYLO
// runtime that a synced group still drives authorization after a restart.
//
// This is the property that would fail silently. A group whose membership
// does not replay denies everybody who held access through it — an outage
// that looks like a policy change — and a group whose *removals* do not
// replay grants access to people the directory took out, which is worse and
// invisible. Membership is checked here by asking the decision engine, not by
// reading the projection, because the projection agreeing with itself proves
// nothing.
func TestRealFYLOProvisionedGroupsSurviveRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}
	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	root, err := os.MkdirTemp("", "sesame-scim-groups-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	now := time.Unix(1_700_000_000, 0).UTC()

	open := func() (*fyloadapter.Client, *identityapp.Service) {
		t.Helper()
		client, err := fyloadapter.Start(ctx, config)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		ledger, events, err := securityledger.Open(ctx, client)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		service, err := identityapp.New(ledger, events)
		if err != nil {
			t.Fatalf("identity.New() error = %v", err)
		}
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	provisioner, _, err := service.ProvisioningClientRegister(ctx, tenant.Tenant.ID,
		"Okta production", "", true, "test:integration")
	if err != nil {
		t.Fatalf("ProvisioningClientRegister() error = %v", err)
	}

	// Two people: one stays in the group, one is removed before the restart.
	stays, err := service.UserProvision(ctx, provisioner,
		scimPayload(t, "stays@example.com"), "test:integration")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}
	removed, err := service.UserProvision(ctx, provisioner,
		scimPayload(t, "removed@example.com"), "test:integration")
	if err != nil {
		t.Fatalf("UserProvision() error = %v", err)
	}

	group, err := service.GroupProvision(ctx, provisioner,
		scimGroupPayload(t, "engineering", stays.ID, removed.ID), "test:integration")
	if err != nil {
		t.Fatalf("GroupProvision() error = %v", err)
	}

	// The group carries a role, which is what makes membership matter.
	role, err := service.RoleCreate(ctx, tenant.Tenant.ID, "deployer",
		[]authzdomain.Permission{{Action: "deploy:run", Resource: "service:api"}},
		"test:integration")
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	if _, err := service.GrantCreateForGroup(ctx, tenant.Tenant.ID, group.ID, role.ID,
		"test:integration"); err != nil {
		t.Fatalf("GrantCreateForGroup() error = %v", err)
	}

	// The directory removes one member before the restart.
	if _, err := service.GroupPatch(ctx, provisioner, group.ID,
		scimGroupRemove(t, removed.ID), "test:integration"); err != nil {
		t.Fatalf("GroupPatch() error = %v", err)
	}
	assertDecision(t, service, tenant.Tenant.ID, stays.ID, identityapp.DecisionAllow,
		"before restart, the remaining member")
	assertDecision(t, service, tenant.Tenant.ID, removed.ID, "deny",
		"before restart, the removed member")

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// ---- restart ----
	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	// The decision engine is asked again. A membership that did not replay
	// denies the wrong person; a removal that did not replay allows them.
	assertDecision(t, replayed, tenant.Tenant.ID, stays.ID, identityapp.DecisionAllow,
		"after restart, the remaining member")
	assertDecision(t, replayed, tenant.Tenant.ID, removed.ID, "deny",
		"after restart, the removed member")

	// The group reads back through the provisioning surface too, with exactly
	// the member the directory left in it.
	after, err := replayed.GroupGet(provisioner, group.ID)
	if err != nil {
		t.Fatalf("GroupGet() after restart error = %v", err)
	}
	if len(after.Members) != 1 || after.Members[0] != stays.ID {
		t.Fatalf("after restart the group holds %#v", after.Members)
	}

	// Emptying the group after a restart takes the access away.
	if err := replayed.GroupDeprovision(ctx, provisioner, group.ID,
		"test:integration"); err != nil {
		t.Fatalf("GroupDeprovision() after restart error = %v", err)
	}
	assertDecision(t, replayed, tenant.Tenant.ID, stays.ID, "deny",
		"after the group was emptied")

	// The group and its grant survive the emptying, so an operator can see
	// what access was removed.
	if _, err := replayed.GroupGetByName(tenant.Tenant.ID, "engineering"); err != nil {
		t.Fatalf("deprovisioning deleted the group: %v", err)
	}
}

// assertDecision asks the decision engine rather than reading a projection.
func assertDecision(
	t *testing.T,
	service *identityapp.Service,
	tenantID, principalID, want, when string,
) {
	t.Helper()

	decision, err := service.Decide(identityapp.DecisionRequest{
		TenantID:    tenantID,
		PrincipalID: principalID,
		Action:      "deploy:run",
		Resource:    "service:api",
	}, nil)
	if err != nil {
		t.Fatalf("%s: Decide() error = %v", when, err)
	}
	if decision.Decision != want {
		t.Fatalf("%s: decision = %q (%s), want %q",
			when, decision.Decision, decision.ReasonCode, want)
	}
}

func scimGroupPayload(t *testing.T, displayName string, members ...string) []byte {
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

func scimGroupRemove(t *testing.T, principalID string) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]any{
		"schemas": []string{scimdomain.SchemaPatch},
		"Operations": []map[string]any{{
			"op":    "remove",
			"path":  "members",
			"value": []map[string]any{{"value": principalID}},
		}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}
