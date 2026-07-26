package sesame

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/adapters/machine"
)

var testBinary string

const testOperationTimeout = 10 * time.Second

func TestMain(m *testing.M) {
	temporaryDirectory, err := os.MkdirTemp("", "sesame-go-client-*")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create test directory: %v\n", err)
		os.Exit(1)
	}
	binaryName := "sesame"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	testBinary = filepath.Join(temporaryDirectory, binaryName)

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		_, _ = fmt.Fprintln(os.Stderr, "locate Go client test file")
		os.Exit(1)
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	build := exec.Command("go", "build", "-trimpath", "-o", testBinary, "./cmd/sesame")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build SESAME test binary: %v\n%s", buildErr, output)
		os.Exit(1)
	}

	exitCode := m.Run()
	_ = os.RemoveAll(temporaryDirectory)
	os.Exit(exitCode)
}

func TestClientDrivesLongLivedMachineProcess(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), Options{
		Binary: testBinary,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	})

	pingContext, cancelPing := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancelPing()
	if err := client.Ping(pingContext); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	versionContext, cancelVersion := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancelVersion()
	info, err := client.Version(versionContext)
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if info.Name != "sesame" || info.Version != "dev" {
		t.Fatalf("Version() = %#v", info)
	}
}

func TestClientReturnsTypedProtocolErrors(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), Options{
		Binary: testBinary,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})

	var result map[string]any
	err = client.Request(context.Background(), "identity.create", struct{}{}, &result)
	protocolError, ok := err.(*ProtocolError)
	if !ok {
		t.Fatalf("Request() error = %T %v, want *ProtocolError", err, err)
	}
	if protocolError.Code != machine.ErrorOperationNotFound || protocolError.Retryable {
		t.Fatalf("protocol error = %#v", protocolError)
	}
}

func TestTenantOperationsFailClosedWithoutStorage(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), Options{Binary: testBinary})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	status, reason, err := client.Readiness(context.Background())
	if err != nil || status != "not_ready" || reason != "storage_not_configured" {
		t.Fatalf("Readiness() = %q, %q, %v", status, reason, err)
	}

	_, err = client.TenantBootstrap(context.Background(), "acme")
	protocolError, ok := err.(*ProtocolError)
	if !ok || protocolError.Code != machine.ErrorStorageNotConfigured {
		t.Fatalf("TenantBootstrap() error = %T %v, want storage_not_configured", err, err)
	}
}

func TestTenantBootstrapThroughStorageBackedChild(t *testing.T) {
	t.Parallel()

	fakeFYLO := filepath.Join(t.TempDir(), "fake-fylo")
	if runtime.GOOS == "windows" {
		fakeFYLO += ".exe"
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate Go client test file")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	build := exec.Command("go", "build", "-trimpath", "-o", fakeFYLO, "./internal/adapters/fylo/testdata/fakefylo")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake FYLO binary: %v\n%s", err, output)
	}
	root := filepath.Join(t.TempDir(), "normal")
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

	requestContext, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	status, _, err := client.Readiness(requestContext)
	if err != nil || status != "ok" {
		t.Fatalf("Readiness() = %q, %v", status, err)
	}

	created, err := client.TenantBootstrap(requestContext, "Acme")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	if !created.Created || created.Tenant.Name != "acme" {
		t.Fatalf("TenantBootstrap() = %#v", created)
	}

	repeated, err := client.TenantBootstrap(requestContext, "acme")
	if err != nil || repeated.Created || repeated.Tenant.ID != created.Tenant.ID {
		t.Fatalf("repeat TenantBootstrap() = %#v, %v", repeated, err)
	}

	byName, err := client.TenantGetByName(requestContext, "acme")
	if err != nil || byName.ID != created.Tenant.ID {
		t.Fatalf("TenantGetByName() = %#v, %v", byName, err)
	}
	byID, err := client.TenantGetByID(requestContext, created.Tenant.ID)
	if err != nil || byID.Name != "acme" {
		t.Fatalf("TenantGetByID() = %#v, %v", byID, err)
	}

	_, err = client.TenantGetByName(requestContext, "missing")
	protocolError, ok := err.(*ProtocolError)
	if !ok || protocolError.Code != machine.ErrorTenantNotFound {
		t.Fatalf("TenantGetByName(missing) error = %T %v", err, err)
	}

	principal, err := client.PrincipalCreate(requestContext, created.Tenant.ID, "human", PrincipalIdentifier{
		Namespace: "email",
		Value:     "Alice@Example.com",
	})
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if principal.Status != "active" || principal.Identifier.Value != "alice@example.com" {
		t.Fatalf("PrincipalCreate() = %#v", principal)
	}

	_, err = client.PrincipalCreate(requestContext, created.Tenant.ID, "workload", PrincipalIdentifier{
		Namespace: "email",
		Value:     "alice@example.com",
	})
	protocolError, ok = err.(*ProtocolError)
	if !ok || protocolError.Code != machine.ErrorIdentifierConflict {
		t.Fatalf("duplicate PrincipalCreate() error = %T %v", err, err)
	}

	resolved, err := client.PrincipalGetByIdentifier(requestContext, created.Tenant.ID, PrincipalIdentifier{
		Namespace: "email",
		Value:     "alice@example.com",
	})
	if err != nil || resolved.ID != principal.ID {
		t.Fatalf("PrincipalGetByIdentifier() = %#v, %v", resolved, err)
	}

	// Authorization: role, grant, decide, revoke.
	role, err := client.RoleCreate(requestContext, created.Tenant.ID, "reader", []Permission{
		{Action: "doc:read", Resource: "*"},
	})
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	grant, err := client.GrantCreate(requestContext, created.Tenant.ID, principal.ID, role.ID)
	if err != nil {
		t.Fatalf("GrantCreate() error = %v", err)
	}
	request := DecisionRequest{
		TenantID:    created.Tenant.ID,
		PrincipalID: principal.ID,
		Action:      "doc:read",
		Resource:    "file:a",
	}
	allowed, err := client.Decide(requestContext, request, nil)
	if err != nil || allowed.Decision != "allow" || allowed.ReasonCode != "allow_role_grant" {
		t.Fatalf("Decide() = %#v, %v", allowed, err)
	}
	pinned := allowed.PolicyVersion
	if _, err := client.Decide(requestContext, request, &pinned); err != nil {
		t.Fatalf("pinned Decide() error = %v", err)
	}
	stale := pinned - 1
	_, err = client.Decide(requestContext, request, &stale)
	protocolError, ok = err.(*ProtocolError)
	if !ok || protocolError.Code != machine.ErrorStalePolicyVersion {
		t.Fatalf("stale Decide() error = %T %v", err, err)
	}
	batch, err := client.DecideBatch(requestContext, []DecisionRequest{
		request,
		{TenantID: created.Tenant.ID, PrincipalID: principal.ID, Action: "doc:write", Resource: "file:a"},
	}, nil)
	if err != nil || len(batch) != 2 || batch[0].Decision != "allow" || batch[1].Decision != "deny" {
		t.Fatalf("DecideBatch() = %#v, %v", batch, err)
	}
	if err := client.GrantRevoke(requestContext, grant.ID); err != nil {
		t.Fatalf("GrantRevoke() error = %v", err)
	}
	afterRevoke, err := client.Decide(requestContext, request, nil)
	if err != nil || afterRevoke.Decision != "deny" || afterRevoke.ReasonCode != "deny_no_grant" {
		t.Fatalf("post-revoke Decide() = %#v, %v", afterRevoke, err)
	}

	suspendedPrincipal, err := client.PrincipalSuspend(requestContext, principal.ID)
	if err != nil || suspendedPrincipal.Status != "suspended" {
		t.Fatalf("PrincipalSuspend() = %#v, %v", suspendedPrincipal, err)
	}
	afterSuspendDecision, err := client.Decide(requestContext, request, nil)
	if err != nil || afterSuspendDecision.ReasonCode != "deny_principal_suspended" {
		t.Fatalf("post-suspend Decide() = %#v, %v", afterSuspendDecision, err)
	}
	byID, err = client.TenantGetByID(requestContext, created.Tenant.ID)
	if err != nil || byID.Status != "active" {
		t.Fatalf("tenant after principal suspension = %#v, %v", byID, err)
	}
	afterSuspend, err := client.PrincipalGetByID(requestContext, principal.ID)
	if err != nil || afterSuspend.Status != "suspended" {
		t.Fatalf("PrincipalGetByID() after suspend = %#v, %v", afterSuspend, err)
	}
}

func TestDecodeResponseRejectsAmbiguousFrames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		frame string
	}{
		{
			name:  "duplicate field",
			frame: `{"protocol_version":"1","request_id":"request-1","ok":true,"ok":false,"result":{}}`,
		},
		{
			name:  "unknown field",
			frame: `{"protocol_version":"1","request_id":"request-1","ok":true,"result":{},"unexpected":true}`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var result map[string]any
			if err := decodeResponse("request-1", []byte(test.frame), &result); err == nil {
				t.Fatalf("decodeResponse(%s) error = nil", test.frame)
			}
		})
	}
}
