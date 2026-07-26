package identity

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// authorizationFixture builds one tenant with a reader role, an editor, and
// two principals; alice holds reader, bob holds nothing.
type authorizationFixture struct {
	service *Service
	ledger  *memoryLedger
	tenant  string
	alice   string
	bob     string
	reader  authzdomain.Role
	grant   authzdomain.Grant
}

func newAuthorizationFixture(t *testing.T) authorizationFixture {
	t.Helper()

	service, ledger, tenantID := bootstrapService(t)
	alice, err := service.PrincipalCreate(
		context.Background(),
		tenantID,
		principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "alice@example.com"},
		"test",
	)
	if err != nil {
		t.Fatalf("PrincipalCreate(alice) error = %v", err)
	}
	bob, err := service.PrincipalCreate(
		context.Background(),
		tenantID,
		principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "bob@example.com"},
		"test",
	)
	if err != nil {
		t.Fatalf("PrincipalCreate(bob) error = %v", err)
	}
	reader, err := service.RoleCreate(context.Background(), tenantID, "Doc-Reader", []authzdomain.Permission{
		{Action: "doc:read", Resource: "project:*"},
		{Action: "doc:list", Resource: "*"},
	}, "test")
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	grant, err := service.GrantCreate(context.Background(), tenantID, alice.ID, reader.ID, "test")
	if err != nil {
		t.Fatalf("GrantCreate() error = %v", err)
	}
	return authorizationFixture{
		service: service,
		ledger:  ledger,
		tenant:  tenantID,
		alice:   alice.ID,
		bob:     bob.ID,
		reader:  reader,
		grant:   grant,
	}
}

func TestGoldenDecisionCorpus(t *testing.T) {
	t.Parallel()

	fixture := newAuthorizationFixture(t)
	unknownPrincipal := "prn_00000000000000000000000000000000"
	unknownTenant := "tnt_00000000000000000000000000000000"

	corpus := []struct {
		name       string
		request    DecisionRequest
		decision   string
		reasonCode string
	}{
		{
			name:       "grant allows matching action and resource",
			request:    DecisionRequest{TenantID: fixture.tenant, PrincipalID: fixture.alice, Action: "doc:read", Resource: "project:alpha"},
			decision:   DecisionAllow,
			reasonCode: ReasonAllowRoleGrant,
		},
		{
			name:       "wildcard resource matches nested segments",
			request:    DecisionRequest{TenantID: fixture.tenant, PrincipalID: fixture.alice, Action: "doc:read", Resource: "project:alpha:file"},
			decision:   DecisionAllow,
			reasonCode: ReasonAllowRoleGrant,
		},
		{
			name:       "action outside the role denies by default",
			request:    DecisionRequest{TenantID: fixture.tenant, PrincipalID: fixture.alice, Action: "doc:delete", Resource: "project:alpha"},
			decision:   DecisionDeny,
			reasonCode: ReasonDenyNoGrant,
		},
		{
			name:       "resource outside the pattern denies by default",
			request:    DecisionRequest{TenantID: fixture.tenant, PrincipalID: fixture.alice, Action: "doc:read", Resource: "billing:invoice"},
			decision:   DecisionDeny,
			reasonCode: ReasonDenyNoGrant,
		},
		{
			name:       "principal without any grant denies",
			request:    DecisionRequest{TenantID: fixture.tenant, PrincipalID: fixture.bob, Action: "doc:read", Resource: "project:alpha"},
			decision:   DecisionDeny,
			reasonCode: ReasonDenyNoGrant,
		},
		{
			name:       "unknown principal denies",
			request:    DecisionRequest{TenantID: fixture.tenant, PrincipalID: unknownPrincipal, Action: "doc:read", Resource: "project:alpha"},
			decision:   DecisionDeny,
			reasonCode: ReasonDenyPrincipalNotFound,
		},
		{
			name:       "unknown tenant denies",
			request:    DecisionRequest{TenantID: unknownTenant, PrincipalID: fixture.alice, Action: "doc:read", Resource: "project:alpha"},
			decision:   DecisionDeny,
			reasonCode: ReasonDenyTenantNotFound,
		},
	}
	for _, test := range corpus {
		decision, err := fixture.service.Decide(test.request, nil)
		if err != nil {
			t.Fatalf("%s: Decide() error = %v", test.name, err)
		}
		if decision.Decision != test.decision || decision.ReasonCode != test.reasonCode {
			t.Fatalf("%s: decision = %#v, want %s/%s", test.name, decision, test.decision, test.reasonCode)
		}
		if decision.DecisionID == "" || decision.PolicyVersion != fixture.service.PolicyVersion() {
			t.Fatalf("%s: decision metadata = %#v", test.name, decision)
		}
	}

	// Cross-tenant substitution: alice's principal ID inside another
	// bootstrapped tenant denies with principal-not-found.
	other, err := fixture.service.Bootstrap(context.Background(), "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap(other) error = %v", err)
	}
	crossTenant, err := fixture.service.Decide(DecisionRequest{
		TenantID:    other.Tenant.ID,
		PrincipalID: fixture.alice,
		Action:      "doc:read",
		Resource:    "project:alpha",
	}, nil)
	if err != nil || crossTenant.Decision != DecisionDeny || crossTenant.ReasonCode != ReasonDenyPrincipalNotFound {
		t.Fatalf("cross-tenant decision = %#v, %v", crossTenant, err)
	}
}

func TestSuspensionAndRevocationDenyDurably(t *testing.T) {
	t.Parallel()

	fixture := newAuthorizationFixture(t)
	request := DecisionRequest{
		TenantID:    fixture.tenant,
		PrincipalID: fixture.alice,
		Action:      "doc:read",
		Resource:    "project:alpha",
	}

	if decision, err := fixture.service.Decide(request, nil); err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("baseline decision = %#v, %v", decision, err)
	}

	// Suspension flips the decision without touching the grant.
	if _, err := fixture.service.PrincipalSuspend(context.Background(), fixture.alice, "test"); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}
	if decision, err := fixture.service.Decide(request, nil); err != nil || decision.ReasonCode != ReasonDenyPrincipalSuspended {
		t.Fatalf("suspended decision = %#v, %v", decision, err)
	}

	// Revocation denies bob-style even after replay from the ledger alone.
	if err := fixture.service.GrantRevoke(context.Background(), fixture.grant.ID, "test"); err != nil {
		t.Fatalf("GrantRevoke() error = %v", err)
	}
	if err := fixture.service.GrantRevoke(context.Background(), fixture.grant.ID, "test"); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("second GrantRevoke() error = %v", err)
	}
	replayed, err := New(nil, fixture.ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	decision, err := replayed.Decide(request, nil)
	if err != nil || decision.Decision != DecisionDeny || decision.ReasonCode != ReasonDenyPrincipalSuspended {
		t.Fatalf("replayed decision = %#v, %v", decision, err)
	}
	if replayed.PolicyVersion() != fixture.service.PolicyVersion() {
		t.Fatalf(
			"replayed policy version %d differs from live %d",
			replayed.PolicyVersion(),
			fixture.service.PolicyVersion(),
		)
	}
}

func TestPolicyVersionPinningAndBatch(t *testing.T) {
	t.Parallel()

	fixture := newAuthorizationFixture(t)
	current := fixture.service.PolicyVersion()
	request := DecisionRequest{
		TenantID:    fixture.tenant,
		PrincipalID: fixture.alice,
		Action:      "doc:read",
		Resource:    "project:alpha",
	}

	pinned, err := fixture.service.Decide(request, &current)
	if err != nil || pinned.PolicyVersion != current {
		t.Fatalf("pinned Decide() = %#v, %v", pinned, err)
	}

	stale := current - 1
	if _, err := fixture.service.Decide(request, &stale); !errors.Is(err, ErrStalePolicyVersion) {
		t.Fatalf("stale Decide() error = %v", err)
	}

	batch, err := fixture.service.DecideBatch([]DecisionRequest{
		request,
		{TenantID: fixture.tenant, PrincipalID: fixture.bob, Action: "doc:read", Resource: "project:alpha"},
	}, nil)
	if err != nil || len(batch) != 2 {
		t.Fatalf("DecideBatch() = %#v, %v", batch, err)
	}
	if batch[0].Decision != DecisionAllow || batch[1].Decision != DecisionDeny {
		t.Fatalf("batch decisions = %#v", batch)
	}
	if batch[0].PolicyVersion != batch[1].PolicyVersion {
		t.Fatal("one batch served mixed policy versions")
	}

	if _, err := fixture.service.DecideBatch(nil, nil); err == nil {
		t.Fatal("DecideBatch() accepted an empty batch")
	}
	oversized := make([]DecisionRequest, 101)
	for index := range oversized {
		oversized[index] = request
	}
	if _, err := fixture.service.DecideBatch(oversized, nil); err == nil {
		t.Fatal("DecideBatch() accepted an oversized batch")
	}
	if _, err := fixture.service.Decide(DecisionRequest{
		TenantID:    fixture.tenant,
		PrincipalID: fixture.alice,
		Action:      "doc:*",
		Resource:    "project:alpha",
	}, nil); err == nil {
		t.Fatal("Decide() accepted a wildcard action")
	}
}

func TestRoleAndGrantUniqueness(t *testing.T) {
	t.Parallel()

	fixture := newAuthorizationFixture(t)

	if _, err := fixture.service.RoleCreate(context.Background(), fixture.tenant, "doc-reader", []authzdomain.Permission{
		{Action: "*", Resource: "*"},
	}, "test"); !errors.Is(err, ErrRoleExists) {
		t.Fatalf("duplicate RoleCreate() error = %v", err)
	}
	if _, err := fixture.service.GrantCreate(context.Background(), fixture.tenant, fixture.alice, fixture.reader.ID, "test"); !errors.Is(err, ErrGrantExists) {
		t.Fatalf("duplicate GrantCreate() error = %v", err)
	}

	byName, err := fixture.service.RoleGetByName(fixture.tenant, "DOC-Reader")
	if err != nil || byName.ID != fixture.reader.ID {
		t.Fatalf("RoleGetByName() = %#v, %v", byName, err)
	}

	// Concurrent duplicate grants: exactly one winner.
	const attempts = 50
	var winners, conflicts atomic.Int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := fixture.service.GrantCreate(context.Background(), fixture.tenant, fixture.bob, fixture.reader.ID, "test")
			switch {
			case err == nil:
				winners.Add(1)
			case errors.Is(err, ErrGrantExists):
				conflicts.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if winners.Load() != 1 || conflicts.Load() != attempts-1 {
		t.Fatalf("winners = %d, conflicts = %d", winners.Load(), conflicts.Load())
	}
}

func TestGroupMembershipDecisions(t *testing.T) {
	t.Parallel()

	fixture := newAuthorizationFixture(t)
	request := DecisionRequest{
		TenantID:    fixture.tenant,
		PrincipalID: fixture.bob,
		Action:      "doc:read",
		Resource:    "project:alpha",
	}

	group, err := fixture.service.GroupCreate(context.Background(), fixture.tenant, "Readers", "test")
	if err != nil {
		t.Fatalf("GroupCreate() error = %v", err)
	}
	if _, err := fixture.service.GroupCreate(context.Background(), fixture.tenant, "readers", "test"); !errors.Is(err, ErrGroupExists) {
		t.Fatalf("duplicate GroupCreate() error = %v", err)
	}
	if _, err := fixture.service.GrantCreateForGroup(context.Background(), fixture.tenant, group.ID, fixture.reader.ID, "test"); err != nil {
		t.Fatalf("GrantCreateForGroup() error = %v", err)
	}
	if _, err := fixture.service.GrantCreateForGroup(context.Background(), fixture.tenant, group.ID, fixture.reader.ID, "test"); !errors.Is(err, ErrGrantExists) {
		t.Fatalf("duplicate GrantCreateForGroup() error = %v", err)
	}

	// Bob is not a member yet: the group grant must not leak.
	if decision, err := fixture.service.Decide(request, nil); err != nil || decision.Decision != DecisionDeny {
		t.Fatalf("pre-membership decision = %#v, %v", decision, err)
	}

	if err := fixture.service.GroupMemberAdd(context.Background(), group.ID, fixture.bob, "test"); err != nil {
		t.Fatalf("GroupMemberAdd() error = %v", err)
	}
	if err := fixture.service.GroupMemberAdd(context.Background(), group.ID, fixture.bob, "test"); !errors.Is(err, ErrGroupMemberExists) {
		t.Fatalf("duplicate GroupMemberAdd() error = %v", err)
	}
	decision, err := fixture.service.Decide(request, nil)
	if err != nil || decision.Decision != DecisionAllow || decision.ReasonCode != ReasonAllowGroupGrant {
		t.Fatalf("membership decision = %#v, %v", decision, err)
	}

	// Removal is durable: deny live and after replay from the ledger alone.
	if err := fixture.service.GroupMemberRemove(context.Background(), group.ID, fixture.bob, "test"); err != nil {
		t.Fatalf("GroupMemberRemove() error = %v", err)
	}
	if err := fixture.service.GroupMemberRemove(context.Background(), group.ID, fixture.bob, "test"); !errors.Is(err, ErrGroupMemberNotFound) {
		t.Fatalf("absent GroupMemberRemove() error = %v", err)
	}
	if decision, err := fixture.service.Decide(request, nil); err != nil || decision.ReasonCode != ReasonDenyNoGrant {
		t.Fatalf("post-removal decision = %#v, %v", decision, err)
	}
	replayed, err := New(nil, fixture.ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	if decision, err := replayed.Decide(request, nil); err != nil || decision.Decision != DecisionDeny {
		t.Fatalf("replayed post-removal decision = %#v, %v", decision, err)
	}
	if replayed.PolicyVersion() != fixture.service.PolicyVersion() {
		t.Fatal("replayed policy version diverged after membership changes")
	}

	// Snapshot state carries groups and memberships.
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)
	if err := fixture.service.GroupMemberAdd(context.Background(), group.ID, fixture.bob, "test"); err != nil {
		t.Fatalf("re-add GroupMemberAdd() error = %v", err)
	}
	restored, err := NewFromSnapshot(nil, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	if decision, err := restored.Decide(request, nil); err != nil || decision.ReasonCode != ReasonAllowGroupGrant {
		t.Fatalf("snapshot membership decision = %#v, %v", decision, err)
	}
}

func TestAuthorizationSnapshotRoundTrip(t *testing.T) {
	t.Parallel()

	fixture := newAuthorizationFixture(t)
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)

	// Trigger one more policy event so a snapshot exists with authz state.
	editor, err := fixture.service.RoleCreate(context.Background(), fixture.tenant, "editor", []authzdomain.Permission{
		{Action: "doc:*", Resource: "*"},
	}, "test")
	if err != nil {
		t.Fatalf("RoleCreate(editor) error = %v", err)
	}
	restored, err := NewFromSnapshot(nil, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	if restored.PolicyVersion() != fixture.service.PolicyVersion() {
		t.Fatalf(
			"snapshot policy version %d differs from live %d",
			restored.PolicyVersion(),
			fixture.service.PolicyVersion(),
		)
	}
	if _, err := restored.RoleGetByName(fixture.tenant, "editor"); err != nil {
		t.Fatalf("snapshot RoleGetByName(editor) error = %v; role %s missing", err, editor.ID)
	}
	decision, err := restored.Decide(DecisionRequest{
		TenantID:    fixture.tenant,
		PrincipalID: fixture.alice,
		Action:      "doc:read",
		Resource:    "project:alpha",
	}, nil)
	if err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("snapshot decision = %#v, %v", decision, err)
	}
}
