package sesame

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The environment path is the one a deployed application actually takes: the
// process is configured once, and `Start` is called with nothing.
//
// This exercises it through a real compiled engine, because the resolution is
// split across two processes — the shim resolves SESAME_BINARY, and the engine
// resolves SESAME_DEPLOYMENT out of the environment it inherits. A test that
// checked either half alone would not prove the pair works.
//
// These cannot run in parallel with anything: t.Setenv is process-wide.

func buildFakeFYLO(t *testing.T, workspace string) string {
	t.Helper()

	binary := filepath.Join(workspace, "fake-fylo")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	_, filename, ok := callerFile()
	if !ok {
		t.Fatal("locate the test file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	build := exec.Command("go", "build", "-trimpath", "-o", binary,
		"./internal/adapters/fylo/testdata/fakefylo")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake FYLO: %v\n%s", err, output)
	}
	return binary
}

func callerFile() (uintptr, string, bool) {
	pc, file, _, ok := runtime.Caller(0)
	return pc, file, ok
}

// TestStartWithNoOptionsUsesTheEnvironment is the shape a deployed
// application uses: configure the process, then call Start with nothing.
func TestStartWithNoOptionsUsesTheEnvironment(t *testing.T) {
	workspace := t.TempDir()
	fakeFYLO := buildFakeFYLO(t, workspace)
	root := filepath.Join(workspace, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	t.Setenv("SESAME_BINARY", testBinary)
	t.Setenv("FYLO_BINARY", fakeFYLO)
	t.Setenv("FYLO_ROOT", root)

	client, err := Start(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Start() with no options error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	// Storage has to be live, not merely connected: a process that started
	// but ignored the environment would still answer system.ping.
	tenant, err := client.TenantBootstrap(ctx, "acme")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	if tenant.Tenant.ID == "" {
		t.Fatalf("bootstrap returned %#v", tenant)
	}
}

// TestExplicitOptionsBeatTheEnvironment guards the precedence in the place it
// is most dangerous to get wrong: an application that names a binary must not
// silently run a different one because a variable was exported.
func TestExplicitOptionsBeatTheEnvironment(t *testing.T) {
	t.Setenv("SESAME_BINARY", filepath.Join(t.TempDir(), "does-not-exist"))

	workspace := t.TempDir()
	fakeFYLO := buildFakeFYLO(t, workspace)
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
		t.Fatalf("an explicit binary lost to SESAME_BINARY: %v", err)
	}
	_ = client.Close()
}

// TestStartReportsAMissingDeploymentClearly: the engine refuses, and the
// refusal has to say what to do. A developer whose volume did not mount sees
// this message and nothing else.
func TestStartReportsAMissingDeploymentClearly(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-created")
	t.Setenv("SESAME_BINARY", testBinary)
	t.Setenv("SESAME_DEPLOYMENT", missing)

	client, err := Start(context.Background(), Options{})
	if err == nil {
		_ = client.Close()
		t.Fatal("Start accepted a deployment directory that does not exist")
	}
	// The engine writes the remedy to stderr and exits. If the shim discarded
	// that, the developer would see only "the process died" and would have no
	// way to learn their volume never mounted.
	for _, expected := range []string{missing, "does not exist", "sesame init"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Start() error = %q, which does not mention %q", err, expected)
		}
	}
}
