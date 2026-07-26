package sesame

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/adapters/machine"
)

// TestSDKContractScenario drives the shared cross-language SDK corpus. The
// Node (clients/node/contract.test.js) and Python
// (clients/python/test_contract.py) suites run the identical sequence, so any
// divergence between SDKs fails in that SDK's own suite.
func TestSDKContractScenario(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	fakeFYLO := filepath.Join(workspace, "fake-fylo")
	if runtime.GOOS == "windows" {
		fakeFYLO += ".exe"
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate contract test file")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	build := exec.Command("go", "build", "-trimpath", "-o", fakeFYLO, "./internal/adapters/fylo/testdata/fakefylo")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake FYLO: %v\n%s", err, output)
	}
	root := filepath.Join(workspace, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	client, err := Start(context.Background(), Options{
		Binary:     testBinary,
		FYLOBinary: fakeFYLO,
		FYLORoot:   root,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	assertCode := func(err error, code string, label string) {
		t.Helper()
		var protocolError *ProtocolError
		if !errors.As(err, &protocolError) || protocolError.Code != code {
			t.Fatalf("%s error = %T %v, want %s", label, err, err, code)
		}
	}

	// 1. System operations report a storage-backed process.
	if status, _, err := client.Readiness(ctx); err != nil || status != "ok" {
		t.Fatalf("Readiness() = %q, %v", status, err)
	}

	// 2. Administrator bootstrap converges.
	admin := PrincipalIdentifier{Namespace: "email", Value: "Admin@Example.com"}
	first, err := client.AdminBootstrap(ctx, "acme", admin)
	if err != nil || !first.Created || first.Role.Name != "administrator" ||
		first.Administrator.Identifier.Value != "admin@example.com" {
		t.Fatalf("AdminBootstrap() = %#v, %v", first, err)
	}
	second, err := client.AdminBootstrap(ctx, "acme", PrincipalIdentifier{
		Namespace: "email",
		Value:     "admin@example.com",
	})
	if err != nil || second.Created || second.Grant.ID != first.Grant.ID {
		t.Fatalf("repeat AdminBootstrap() = %#v, %v", second, err)
	}
	adminDecision, err := client.Decide(ctx, DecisionRequest{
		TenantID:    first.Tenant.ID,
		PrincipalID: first.Administrator.ID,
		Action:      "tenant:configure",
		Resource:    "deployment:root",
	}, nil)
	if err != nil || adminDecision.Decision != "allow" {
		t.Fatalf("administrator Decide() = %#v, %v", adminDecision, err)
	}

	// 3. Principals, identifiers, roles, grants, and decisions.
	tenantID := first.Tenant.ID
	alice, err := client.PrincipalCreate(ctx, tenantID, "human", PrincipalIdentifier{
		Namespace: "email",
		Value:     "Alice@Example.com",
	})
	if err != nil || alice.Identifier.Value != "alice@example.com" || alice.Status != "active" {
		t.Fatalf("PrincipalCreate() = %#v, %v", alice, err)
	}
	_, err = client.PrincipalCreate(ctx, tenantID, "workload", PrincipalIdentifier{
		Namespace: "email",
		Value:     "alice@example.com",
	})
	assertCode(err, machine.ErrorIdentifierConflict, "duplicate PrincipalCreate()")

	role, err := client.RoleCreate(ctx, tenantID, "reader", []Permission{
		{Action: "doc:read", Resource: "project:*"},
	})
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	request := DecisionRequest{
		TenantID:    tenantID,
		PrincipalID: alice.ID,
		Action:      "doc:read",
		Resource:    "project:alpha",
	}
	if denied, err := client.Decide(ctx, request, nil); err != nil ||
		denied.Decision != "deny" || denied.ReasonCode != "deny_no_grant" {
		t.Fatalf("pre-grant Decide() = %#v, %v", denied, err)
	}
	grant, err := client.GrantCreate(ctx, tenantID, alice.ID, role.ID)
	if err != nil {
		t.Fatalf("GrantCreate() error = %v", err)
	}
	allowed, err := client.Decide(ctx, request, nil)
	if err != nil || allowed.Decision != "allow" || allowed.ReasonCode != "allow_role_grant" {
		t.Fatalf("post-grant Decide() = %#v, %v", allowed, err)
	}
	stale := allowed.PolicyVersion - 1
	_, err = client.Decide(ctx, request, &stale)
	assertCode(err, machine.ErrorStalePolicyVersion, "stale Decide()")
	batch, err := client.DecideBatch(ctx, []DecisionRequest{
		request,
		{TenantID: tenantID, PrincipalID: alice.ID, Action: "doc:delete", Resource: "project:alpha"},
	}, nil)
	if err != nil || len(batch) != 2 || batch[0].Decision != "allow" || batch[1].Decision != "deny" ||
		batch[0].PolicyVersion != batch[1].PolicyVersion {
		t.Fatalf("DecideBatch() = %#v, %v", batch, err)
	}
	if err := client.GrantRevoke(ctx, grant.ID); err != nil {
		t.Fatalf("GrantRevoke() error = %v", err)
	}
	if revoked, err := client.Decide(ctx, request, nil); err != nil || revoked.Decision != "deny" {
		t.Fatalf("post-revoke Decide() = %#v, %v", revoked, err)
	}

	// 4. Group membership drives decisions and removal denies.
	bob, err := client.PrincipalCreate(ctx, tenantID, "human", PrincipalIdentifier{
		Namespace: "email",
		Value:     "bob@example.com",
	})
	if err != nil {
		t.Fatalf("PrincipalCreate(bob) error = %v", err)
	}
	groupRole, err := client.RoleCreate(ctx, tenantID, "group-reader", []Permission{
		{Action: "doc:read", Resource: "*"},
	})
	if err != nil {
		t.Fatalf("RoleCreate(group-reader) error = %v", err)
	}
	group, err := client.GroupCreate(ctx, tenantID, "readers")
	if err != nil {
		t.Fatalf("GroupCreate() error = %v", err)
	}
	if _, err := client.GrantCreateForGroup(ctx, tenantID, group.ID, groupRole.ID); err != nil {
		t.Fatalf("GrantCreateForGroup() error = %v", err)
	}
	groupRequest := DecisionRequest{
		TenantID:    tenantID,
		PrincipalID: bob.ID,
		Action:      "doc:read",
		Resource:    "file:a",
	}
	if decision, err := client.Decide(ctx, groupRequest, nil); err != nil || decision.Decision != "deny" {
		t.Fatalf("pre-membership Decide() = %#v, %v", decision, err)
	}
	if err := client.GroupMemberAdd(ctx, group.ID, bob.ID); err != nil {
		t.Fatalf("GroupMemberAdd() error = %v", err)
	}
	memberDecision, err := client.Decide(ctx, groupRequest, nil)
	if err != nil || memberDecision.ReasonCode != "allow_group_grant" {
		t.Fatalf("membership Decide() = %#v, %v", memberDecision, err)
	}
	assertCode(client.GroupMemberAdd(ctx, group.ID, bob.ID), machine.ErrorGroupMemberExists, "duplicate GroupMemberAdd()")
	if err := client.GroupMemberRemove(ctx, group.ID, bob.ID); err != nil {
		t.Fatalf("GroupMemberRemove() error = %v", err)
	}
	if decision, err := client.Decide(ctx, groupRequest, nil); err != nil || decision.Decision != "deny" {
		t.Fatalf("post-removal Decide() = %#v, %v", decision, err)
	}

	// 5. Suspension denies and unknown records return stable codes.
	carol, err := client.PrincipalCreate(ctx, tenantID, "workload", PrincipalIdentifier{
		Namespace: "login",
		Value:     "carol",
	})
	if err != nil {
		t.Fatalf("PrincipalCreate(carol) error = %v", err)
	}
	jobRole, err := client.RoleCreate(ctx, tenantID, "suspendable", []Permission{
		{Action: "job:run", Resource: "*"},
	})
	if err != nil {
		t.Fatalf("RoleCreate(suspendable) error = %v", err)
	}
	if _, err := client.GrantCreate(ctx, tenantID, carol.ID, jobRole.ID); err != nil {
		t.Fatalf("GrantCreate(carol) error = %v", err)
	}
	jobRequest := DecisionRequest{
		TenantID:    tenantID,
		PrincipalID: carol.ID,
		Action:      "job:run",
		Resource:    "queue:default",
	}
	if decision, err := client.Decide(ctx, jobRequest, nil); err != nil || decision.Decision != "allow" {
		t.Fatalf("pre-suspension Decide() = %#v, %v", decision, err)
	}
	if suspended, err := client.PrincipalSuspend(ctx, carol.ID); err != nil || suspended.Status != "suspended" {
		t.Fatalf("PrincipalSuspend() = %#v, %v", suspended, err)
	}
	afterSuspend, err := client.Decide(ctx, jobRequest, nil)
	if err != nil || afterSuspend.ReasonCode != "deny_principal_suspended" {
		t.Fatalf("post-suspension Decide() = %#v, %v", afterSuspend, err)
	}

	_, err = client.TenantGetByName(ctx, "missing")
	assertCode(err, machine.ErrorTenantNotFound, "TenantGetByName(missing)")
	_, err = client.PrincipalGetByID(ctx, "prn_00000000000000000000000000000000")
	assertCode(err, machine.ErrorPrincipalNotFound, "PrincipalGetByID(missing)")
	var unused map[string]any
	err = client.Request(ctx, "identity.unknown", struct{}{}, &unused)
	assertCode(err, machine.ErrorOperationNotFound, "unknown operation")

}

// TestSDKGoldenDecisionCorpus drives the shared decision fixture through the
// Go SDK. The Node and Python suites load the same file, and the engine test
// asserts the same outcomes directly, so the semantics have one definition.
func TestSDKGoldenDecisionCorpus(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	fakeFYLO := filepath.Join(workspace, "fake-fylo")
	if runtime.GOOS == "windows" {
		fakeFYLO += ".exe"
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate contract test file")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	build := exec.Command("go", "build", "-trimpath", "-o", fakeFYLO, "./internal/adapters/fylo/testdata/fakefylo")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake FYLO: %v\n%s", err, output)
	}
	root := filepath.Join(workspace, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	encoded, err := os.ReadFile(filepath.Join(repositoryRoot, "api", "machine", "v1", "decisions.golden.json"))
	if err != nil {
		t.Fatalf("read golden corpus: %v", err)
	}
	var corpus struct {
		Setup struct {
			Tenant      string `json:"tenant"`
			OtherTenant string `json:"other_tenant"`
			Principals  []struct {
				Name, Kind, Namespace, Value string
			} `json:"principals"`
			Roles []struct {
				Name        string       `json:"name"`
				Permissions []Permission `json:"permissions"`
			} `json:"roles"`
			Groups []struct {
				Name    string   `json:"name"`
				Members []string `json:"members"`
			} `json:"groups"`
			Grants []struct {
				Role, Principal, Group string
			} `json:"grants"`
			Suspended []string `json:"suspended"`
		} `json:"setup"`
		Cases []struct {
			Name        string            `json:"name"`
			Principal   string            `json:"principal"`
			PrincipalID string            `json:"principal_id"`
			Tenant      string            `json:"tenant"`
			TenantID    string            `json:"tenant_id"`
			Action      string            `json:"action"`
			Resource    string            `json:"resource"`
			Context     map[string]string `json:"context"`
			Decision    string            `json:"decision"`
			ReasonCode  string            `json:"reason_code"`
			MissingKey  string            `json:"missing_context_key"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(encoded, &corpus); err != nil {
		t.Fatalf("decode golden corpus: %v", err)
	}

	client, err := Start(context.Background(), Options{
		Binary:     testBinary,
		FYLOBinary: fakeFYLO,
		FYLORoot:   root,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	tenant, err := client.TenantBootstrap(ctx, corpus.Setup.Tenant)
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	other, err := client.TenantBootstrap(ctx, corpus.Setup.OtherTenant)
	if err != nil {
		t.Fatalf("TenantBootstrap(other) error = %v", err)
	}

	principals := map[string]string{}
	for _, wanted := range corpus.Setup.Principals {
		created, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, wanted.Kind, PrincipalIdentifier{
			Namespace: wanted.Namespace,
			Value:     wanted.Value,
		})
		if err != nil {
			t.Fatalf("PrincipalCreate(%s) error = %v", wanted.Name, err)
		}
		principals[wanted.Name] = created.ID
	}
	roles := map[string]string{}
	for _, wanted := range corpus.Setup.Roles {
		created, err := client.RoleCreate(ctx, tenant.Tenant.ID, wanted.Name, wanted.Permissions)
		if err != nil {
			t.Fatalf("RoleCreate(%s) error = %v", wanted.Name, err)
		}
		roles[wanted.Name] = created.ID
	}
	groups := map[string]string{}
	for _, wanted := range corpus.Setup.Groups {
		created, err := client.GroupCreate(ctx, tenant.Tenant.ID, wanted.Name)
		if err != nil {
			t.Fatalf("GroupCreate(%s) error = %v", wanted.Name, err)
		}
		groups[wanted.Name] = created.ID
		for _, member := range wanted.Members {
			if err := client.GroupMemberAdd(ctx, created.ID, principals[member]); err != nil {
				t.Fatalf("GroupMemberAdd(%s) error = %v", member, err)
			}
		}
	}
	for _, wanted := range corpus.Setup.Grants {
		var err error
		if wanted.Group != "" {
			_, err = client.GrantCreateForGroup(ctx, tenant.Tenant.ID, groups[wanted.Group], roles[wanted.Role])
		} else {
			_, err = client.GrantCreate(ctx, tenant.Tenant.ID, principals[wanted.Principal], roles[wanted.Role])
		}
		if err != nil {
			t.Fatalf("grant %s error = %v", wanted.Role, err)
		}
	}
	for _, name := range corpus.Setup.Suspended {
		if _, err := client.PrincipalSuspend(ctx, principals[name]); err != nil {
			t.Fatalf("PrincipalSuspend(%s) error = %v", name, err)
		}
	}

	for _, test := range corpus.Cases {
		request := DecisionRequest{
			TenantID:    tenant.Tenant.ID,
			PrincipalID: principals[test.Principal],
			Action:      test.Action,
			Resource:    test.Resource,
			Context:     test.Context,
		}
		if test.PrincipalID != "" {
			request.PrincipalID = test.PrincipalID
		}
		if test.Tenant == "other" {
			request.TenantID = other.Tenant.ID
		}
		if test.TenantID != "" {
			request.TenantID = test.TenantID
		}

		decision, err := client.Decide(ctx, request, nil)
		if err != nil {
			t.Fatalf("%s: Decide() error = %v", test.Name, err)
		}
		if decision.Decision != test.Decision || decision.ReasonCode != test.ReasonCode ||
			decision.MissingKey != test.MissingKey {
			t.Fatalf(
				"%s: decision = %s/%s/%q, want %s/%s/%q",
				test.Name,
				decision.Decision, decision.ReasonCode, decision.MissingKey,
				test.Decision, test.ReasonCode, test.MissingKey,
			)
		}
	}
}

// TestSDKAuthenticationFlow drives the login flow through the Go SDK. The
// Node and Python suites run the identical sequence.
func TestSDKAuthenticationFlow(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	fakeFYLO := filepath.Join(workspace, "fake-fylo")
	if runtime.GOOS == "windows" {
		fakeFYLO += ".exe"
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate contract test file")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	build := exec.Command("go", "build", "-trimpath", "-o", fakeFYLO, "./internal/adapters/fylo/testdata/fakefylo")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake FYLO: %v\n%s", err, output)
	}
	root := filepath.Join(workspace, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	client, err := Start(context.Background(), Options{
		Binary:     testBinary,
		FYLOBinary: fakeFYLO,
		FYLORoot:   root,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	tenant, err := client.TenantBootstrap(ctx, "authn-acme")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	identifier := PrincipalIdentifier{Namespace: "email", Value: "login@example.com"}
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	const password = "correct horse battery staple"
	if err := client.SetPassword(ctx, principal.ID, password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}

	begun, err := client.AuthenticationBegin(ctx, tenant.Tenant.ID, PrincipalIdentifier{
		Namespace: "email", Value: "Login@Example.com",
	})
	if err != nil || begun.State != "awaiting_factor" {
		t.Fatalf("AuthenticationBegin() = %#v, %v", begun, err)
	}
	wrong, err := client.AuthenticationVerifyPassword(ctx, begun.TransactionID, "wrong password value")
	if err != nil || wrong.AttemptsLeft != 4 {
		t.Fatalf("wrong password = %#v, %v", wrong, err)
	}
	verified, err := client.AuthenticationVerifyPassword(ctx, begun.TransactionID, password)
	if err != nil || verified.Assurance != "password" {
		t.Fatalf("AuthenticationVerifyPassword() = %#v, %v", verified, err)
	}
	issued, err := client.AuthenticationComplete(ctx, begun.TransactionID, time.Hour)
	if err != nil || issued.Secret == "" {
		t.Fatalf("AuthenticationComplete() = %#v, %v", issued, err)
	}

	session, err := client.SessionVerify(ctx, issued.SessionID, issued.Secret)
	if err != nil || session.PrincipalID != principal.ID {
		t.Fatalf("SessionVerify() = %#v, %v", session, err)
	}
	_, err = client.SessionVerify(ctx, issued.SessionID, "nope")
	protocolError, ok := err.(*ProtocolError)
	if !ok || protocolError.Code != machine.ErrorSessionNotFound {
		t.Fatalf("wrong-secret SessionVerify() error = %T %v", err, err)
	}
	if err := client.SessionRevoke(ctx, issued.SessionID, "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	_, err = client.SessionVerify(ctx, issued.SessionID, issued.Secret)
	protocolError, ok = err.(*ProtocolError)
	if !ok || protocolError.Code != machine.ErrorSessionInactive {
		t.Fatalf("revoked SessionVerify() error = %T %v", err, err)
	}

	// An unknown identifier is indistinguishable from a known one.
	unknown, err := client.AuthenticationBegin(ctx, tenant.Tenant.ID, PrincipalIdentifier{
		Namespace: "email", Value: "ghost@example.com",
	})
	if err != nil || unknown.State != begun.State {
		t.Fatalf("unknown AuthenticationBegin() = %#v, %v", unknown, err)
	}
	attempt, err := client.AuthenticationVerifyPassword(ctx, unknown.TransactionID, password)
	if err != nil || attempt.Assurance != "" || attempt.AttemptsLeft != 4 {
		t.Fatalf("unknown identifier attempt = %#v, %v", attempt, err)
	}
}
