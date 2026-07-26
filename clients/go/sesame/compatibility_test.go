package sesame

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestStartVerifiesTheEngine covers the handshake Start performs. Finding a
// mismatched engine here beats finding it partway through a login.
func TestStartVerifiesTheEngine(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	client, err := Start(ctx, Options{Binary: testBinary})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	version, err := client.Version(ctx)
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if version.ProtocolVersion != ProtocolVersion {
		t.Fatalf("engine protocol %q, client protocol %q",
			version.ProtocolVersion, ProtocolVersion)
	}
	// The engine reports what it routes, so a client can ask before it
	// depends on something.
	if len(version.Operations) == 0 {
		t.Fatal("the engine reported no operations")
	}
	if !sortedStrings(version.Operations) {
		t.Fatalf("the reported operations are not sorted: %v", version.Operations)
	}
}

func sortedStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] > values[index] {
			return false
		}
	}
	return true
}

// TestStartRefusesAnEngineSpeakingAnotherProtocol builds a stand-in that
// answers system.version with a different protocol version, and proves Start
// refuses it rather than proceeding into a conversation it cannot trust.
func TestStartRefusesAnEngineSpeakingAnotherProtocol(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	source := filepath.Join(workspace, "main.go")
	// A minimal impostor: correct framing, wrong protocol version. This is
	// exactly the shape a future SESAME 2 would have to a version 1 client.
	if err := os.WriteFile(source, []byte(`package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var request struct {
			RequestID string `+"`json:\"request_id\"`"+`
			Operation string `+"`json:\"operation\"`"+`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			continue
		}
		fmt.Printf(`+"`"+`{"protocol_version":"1","request_id":%q,"ok":true,"result":{"name":"sesame","version":"9.9.9","protocol_version":"2","operations":["system.version"]}}`+"`"+`+"\n", request.RequestID)
	}
}
`), 0o600); err != nil {
		t.Fatalf("write impostor: %v", err)
	}
	impostor := filepath.Join(workspace, "impostor")
	if runtime.GOOS == "windows" {
		impostor += ".exe"
	}
	if err := os.WriteFile(filepath.Join(workspace, "go.mod"),
		[]byte("module impostor\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatalf("write impostor module: %v", err)
	}
	build := exec.Command("go", "build", "-trimpath", "-o", impostor, ".")
	build.Dir = workspace
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build impostor: %v\n%s", err, output)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	client, err := Start(ctx, Options{Binary: impostor})
	if err == nil {
		_ = client.Close()
		t.Fatal("Start accepted an engine speaking another protocol version")
	}
	var incompatible *IncompatibleEngineError
	if !errors.As(err, &incompatible) {
		t.Fatalf("Start() error = %T %v, want IncompatibleEngineError", err, err)
	}
	// The message must name both sides: the fix is to change one of them.
	if !strings.Contains(err.Error(), `"2"`) || !strings.Contains(err.Error(), `"1"`) {
		t.Fatalf("error does not name both protocol versions: %v", err)
	}
	if incompatible.EngineVersion != "9.9.9" {
		t.Fatalf("engine version = %q", incompatible.EngineVersion)
	}

	// The escape hatch exists for tests that mean to drive such an engine.
	skipped, err := Start(ctx, Options{Binary: impostor, SkipCompatibilityCheck: true})
	if err != nil {
		t.Fatalf("Start with SkipCompatibilityCheck error = %v", err)
	}
	_ = skipped.Close()
}

// TestRequireOperationsNamesWhatIsMissing covers the check an application runs
// for the operations it actually depends on.
func TestRequireOperationsNamesWhatIsMissing(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	client, err := Start(ctx, Options{Binary: testBinary})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Everything this client exposes is routed by an engine of the same build.
	if err := client.RequireOperations(ctx,
		"oidc.authorize", "oidc.token", "authn.verify_passkey", "oidc.logout"); err != nil {
		t.Fatalf("RequireOperations() error = %v", err)
	}

	err = client.RequireOperations(ctx, "oidc.authorize", "oidc.imaginary", "oidc.also_imaginary")
	var incompatible *IncompatibleEngineError
	if !errors.As(err, &incompatible) {
		t.Fatalf("RequireOperations() error = %T %v, want IncompatibleEngineError", err, err)
	}
	if len(incompatible.MissingOperations) != 2 ||
		incompatible.MissingOperations[0] != "oidc.also_imaginary" {
		t.Fatalf("missing = %#v, want both, sorted", incompatible.MissingOperations)
	}
	// The message says which ones, so the operator can act without a debugger.
	if !strings.Contains(err.Error(), "oidc.imaginary") {
		t.Fatalf("error does not name the missing operation: %v", err)
	}
}
