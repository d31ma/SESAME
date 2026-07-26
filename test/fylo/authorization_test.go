package fylo_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// TestRealFYLOAuthorizationRevocationSurvivesRestart proves that a grant
// revocation is durable: after the grant allows a decision, revoking it and
// killing the process must replay to a deny at the same policy version.
func TestRealFYLOAuthorizationRevocationSurvivesRestart(t *testing.T) {
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

	root, err := os.MkdirTemp("", "sesame-authorization-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

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

	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	principal, err := service.PrincipalCreate(
		ctx,
		tenant.Tenant.ID,
		principaldomain.KindWorkload,
		principaldomain.Identifier{Namespace: "login", Value: "ci-runner"},
		"test:integration",
	)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	role, err := service.RoleCreate(ctx, tenant.Tenant.ID, "deployer", []authzdomain.Permission{
		{Action: "deploy:*", Resource: "env:staging"},
	}, "test:integration")
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	grant, err := service.GrantCreate(ctx, tenant.Tenant.ID, principal.ID, role.ID, "test:integration")
	if err != nil {
		t.Fatalf("GrantCreate() error = %v", err)
	}

	request := identityapp.DecisionRequest{
		TenantID:    tenant.Tenant.ID,
		PrincipalID: principal.ID,
		Action:      "deploy:run",
		Resource:    "env:staging",
	}
	allowed, err := service.Decide(request, nil)
	if err != nil || allowed.Decision != identityapp.DecisionAllow {
		t.Fatalf("granted decision = %#v, %v", allowed, err)
	}

	if err := service.GrantRevoke(ctx, grant.ID, "test:integration"); err != nil {
		t.Fatalf("GrantRevoke() error = %v", err)
	}
	revokedVersion := service.PolicyVersion()

	// Die without a clean shutdown; the revocation must replay.
	if err := client.Crash(); err != nil {
		t.Fatalf("Crash() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	restarted, err := fyloadapter.Start(ctx, config)
	if err != nil {
		t.Fatalf("restart Start() error = %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	_, replayed, err := securityledger.Open(ctx, restarted)
	if err != nil {
		t.Fatalf("restart Open() error = %v", err)
	}
	rebuilt, err := identityapp.New(nil, replayed)
	if err != nil {
		t.Fatalf("restart identity.New() error = %v", err)
	}
	if rebuilt.PolicyVersion() != revokedVersion {
		t.Fatalf(
			"replayed policy version %d differs from pre-crash %d",
			rebuilt.PolicyVersion(),
			revokedVersion,
		)
	}
	decision, err := rebuilt.Decide(request, &revokedVersion)
	if err != nil {
		t.Fatalf("replayed Decide() error = %v", err)
	}
	if decision.Decision != identityapp.DecisionDeny || decision.ReasonCode != identityapp.ReasonDenyNoGrant {
		t.Fatalf("replayed decision = %#v, want durable deny", decision)
	}
}
