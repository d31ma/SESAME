package fylo_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	fyloproving "github.com/d31ma/sesame/internal/proving/fylo"
)

// TestRealFYLOTenantBootstrapSurvivesRestart proves the production security
// ledger and tenant projection against a real FYLO runtime: bootstrap once,
// kill the process, and verify an independent replay reaches the same tenant.
func TestRealFYLOTenantBootstrapSurvivesRestart(t *testing.T) {
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

	root, err := os.MkdirTemp("", "sesame-tenant-bootstrap-*")
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
	if len(events) != 0 {
		t.Fatalf("fresh root replayed %d events", len(events))
	}
	service, err := identityapp.New(ledger, events)
	if err != nil {
		t.Fatalf("tenant.New() error = %v", err)
	}

	created, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if !created.Created {
		t.Fatalf("Bootstrap() = %#v", created)
	}
	repeated, err := service.Bootstrap(ctx, "ACME", "test:integration")
	if err != nil || repeated.Created || repeated.Tenant.ID != created.Tenant.ID {
		t.Fatalf("repeat Bootstrap() = %#v, %v", repeated, err)
	}

	// Kill without a clean shutdown: the acknowledged event must survive.
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
	_, replayed, err := securityledger.Open(ctx, restarted)
	if err != nil {
		t.Fatalf("restart Open() error = %v", err)
	}
	if len(replayed) != 1 {
		t.Fatalf("restart replayed %d events, want 1", len(replayed))
	}
	rebuilt, err := identityapp.New(nil, replayed)
	if err != nil {
		t.Fatalf("restart tenant.New() error = %v", err)
	}
	byName, err := rebuilt.GetByName("acme")
	if err != nil || byName.ID != created.Tenant.ID || byName.Status != "active" {
		t.Fatalf("restart GetByName() = %#v, %v", byName, err)
	}
	if _, err := rebuilt.GetByName("missing"); !errors.Is(err, identityapp.ErrNotFound) {
		t.Fatalf("restart GetByName(missing) error = %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatalf("restart Close() error = %v", err)
	}

	// Rebuild: destroy the derived index, rebuild it, and prove the same
	// tenant decision from authoritative documents alone.
	if err := fyloproving.RemoveDerivedIndex(config.Root, securityledger.Collection); err != nil {
		t.Fatalf("RemoveDerivedIndex: %v", err)
	}
	assertTenantSurvives(ctx, t, config, created.Tenant.ID, "index rebuild", func(client *fyloadapter.Client) {
		var rebuildResult map[string]any
		if err := client.Request(ctx, "rebuildCollection", map[string]any{
			"collection": securityledger.Collection,
		}, &rebuildResult); err != nil {
			t.Fatalf("rebuildCollection: %v", err)
		}
	})

	// Backup/restore: cold-copy the stopped root into a distinct root and
	// prove the same tenant decision there.
	restoreRoot := filepath.Join(root, "restored")
	if err := os.Mkdir(restoreRoot, 0o700); err != nil {
		t.Fatalf("Mkdir(restored): %v", err)
	}
	if err := fyloproving.CopyTree(config.Root, restoreRoot); err != nil {
		t.Fatalf("CopyTree: %v", err)
	}
	restoreConfig := config
	restoreConfig.Root = restoreRoot
	assertTenantSurvives(ctx, t, restoreConfig, created.Tenant.ID, "cold restore", nil)

	// Interrupted upgrade: write with the pinned binary, die without a clean
	// shutdown, and replay with the next candidate binary. Enabled when the
	// environment provides the upgrade candidate.
	nextBinary := os.Getenv("SESAME_FYLO_NEXT_BINARY")
	nextVersion := os.Getenv("SESAME_FYLO_NEXT_VERSION")
	if nextBinary == "" || nextVersion == "" {
		t.Log("SESAME_FYLO_NEXT_BINARY/SESAME_FYLO_NEXT_VERSION not set; skipping interrupted-upgrade leg")
		return
	}

	preUpgrade, err := fyloadapter.Start(ctx, config)
	if err != nil {
		t.Fatalf("pre-upgrade Start() error = %v", err)
	}
	preUpgradeLedger, preUpgradeEvents, err := securityledger.Open(ctx, preUpgrade)
	if err != nil {
		t.Fatalf("pre-upgrade Open() error = %v", err)
	}
	preUpgradeService, err := identityapp.New(preUpgradeLedger, preUpgradeEvents)
	if err != nil {
		t.Fatalf("pre-upgrade tenant.New() error = %v", err)
	}
	if _, err := preUpgradeService.Bootstrap(ctx, "upgraded", "test:integration"); err != nil {
		t.Fatalf("pre-upgrade Bootstrap() error = %v", err)
	}
	if err := preUpgrade.Crash(); err != nil {
		t.Fatalf("pre-upgrade Crash() error = %v", err)
	}
	if err := preUpgrade.Close(); err != nil {
		t.Fatalf("pre-upgrade Close() error = %v", err)
	}

	upgradeConfig := config
	upgradeConfig.Binary = nextBinary
	upgradeConfig.ExpectedRuntimeVersion = nextVersion
	upgradeConfig.AllowDevelopmentBuild = config.AllowDevelopmentBuild ||
		os.Getenv("SESAME_FYLO_NEXT_ALLOW_DEVELOPMENT") == "1"
	upgraded, err := fyloadapter.Start(ctx, upgradeConfig)
	if err != nil {
		t.Fatalf("upgraded Start() error = %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	upgradedLedger, upgradedEvents, err := securityledger.Open(ctx, upgraded)
	if err != nil {
		t.Fatalf("upgraded Open() error = %v", err)
	}
	if len(upgradedEvents) != 2 {
		t.Fatalf("upgraded replay produced %d events, want 2", len(upgradedEvents))
	}
	upgradedService, err := identityapp.New(upgradedLedger, upgradedEvents)
	if err != nil {
		t.Fatalf("upgraded tenant.New() error = %v", err)
	}
	for _, name := range []string{"acme", "upgraded"} {
		if _, err := upgradedService.GetByName(name); err != nil {
			t.Fatalf("upgraded GetByName(%s) error = %v", name, err)
		}
	}
	// The upgraded binary continues the same chain.
	postUpgrade, err := upgradedService.Bootstrap(ctx, "post-upgrade", "test:integration")
	if err != nil || !postUpgrade.Created {
		t.Fatalf("post-upgrade Bootstrap() = %#v, %v", postUpgrade, err)
	}
}

// assertTenantSurvives starts one FYLO process for config, optionally runs a
// preparation step, and fails the test unless the bootstrap tenant replays
// with a verified chain.
func assertTenantSurvives(
	ctx context.Context,
	t *testing.T,
	config fyloadapter.Config,
	tenantID string,
	step string,
	prepare func(client *fyloadapter.Client),
) {
	t.Helper()

	client, err := fyloadapter.Start(ctx, config)
	if err != nil {
		t.Fatalf("%s Start() error = %v", step, err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Fatalf("%s Close() error = %v", step, err)
		}
	}()
	if prepare != nil {
		prepare(client)
	}
	_, events, err := securityledger.Open(ctx, client)
	if err != nil {
		t.Fatalf("%s Open() error = %v", step, err)
	}
	service, err := identityapp.New(nil, events)
	if err != nil {
		t.Fatalf("%s tenant.New() error = %v", step, err)
	}
	found, err := service.GetByName("acme")
	if err != nil || found.ID != tenantID {
		t.Fatalf("%s GetByName() = %#v, %v", step, found, err)
	}
}
