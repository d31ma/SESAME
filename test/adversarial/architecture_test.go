package adversarial_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestEngineOpensNoNetworkListener is a Phase 4 exit criterion checked
// mechanically rather than by review.
//
// "SESAME does not open a network port" is the load-bearing claim behind the
// whole host-owned-server architecture: the host owns TLS, routing, trusted
// proxies, and request limits, and SESAME talks to it over stdin and stdout.
// A future change that pulled in an HTTP server would break that silently, so
// the linked binary is inspected instead of trusted.
func TestEngineOpensNoNetworkListener(t *testing.T) {
	t.Parallel()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate the architecture test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))

	list := exec.Command("go", "list", "-deps", "./cmd/sesame")
	list.Dir = root
	output, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, output)
	}

	// net/http is the one that matters: linking it is how a listener arrives.
	// `net` alone is unavoidable — os/exec and the runtime reach it — and
	// carries no server.
	forbidden := map[string]string{
		"net/http":     "an HTTP server or client belongs in the host application, not the engine",
		"net/http/cgi": "the engine serves no requests",
		"net/rpc":      "the engine exposes no network RPC",
	}
	for _, line := range strings.Split(string(output), "\n") {
		dependency := strings.TrimSpace(line)
		if reason, banned := forbidden[dependency]; banned {
			t.Fatalf("the SESAME engine links %s: %s", dependency, reason)
		}
	}
}

// TestEngineShipsNoUserInterface is the other half of the same claim. A
// rendered page inside the engine would make the interaction contract
// optional, and the contract is what keeps security decisions in one place.
func TestEngineShipsNoUserInterface(t *testing.T) {
	t.Parallel()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate the architecture test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))

	list := exec.Command("go", "list", "-deps", "./cmd/sesame")
	list.Dir = root
	output, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		dependency := strings.TrimSpace(line)
		if dependency == "html/template" || dependency == "text/template" {
			t.Fatalf("the SESAME engine links %s; rendering belongs to the host", dependency)
		}
	}
}

// TestEngineDependencySurfaceStaysSmall pins the supply-chain claim. SESAME
// has exactly one external dependency — golang.org/x/crypto, for Argon2id —
// and adding a second should be a deliberate decision with an ADR, not
// something that arrives with a convenient import.
func TestEngineDependencySurfaceStaysSmall(t *testing.T) {
	t.Parallel()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate the architecture test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))

	list := exec.Command("go", "list", "-deps", "-f", "{{.Module}}", "./cmd/sesame")
	list.Dir = root
	output, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, output)
	}

	allowed := map[string]struct{}{
		"":                        {}, // standard library
		"<nil>":                   {},
		"github.com/d31ma/sesame": {},
		"golang.org/x/crypto":     {},
		"golang.org/x/sys":        {}, // transitive, required by x/crypto
	}
	unexpected := map[string]struct{}{}
	for _, line := range strings.Split(string(output), "\n") {
		module := strings.TrimSpace(line)
		if index := strings.Index(module, " "); index >= 0 {
			module = module[:index]
		}
		if _, ok := allowed[module]; ok {
			continue
		}
		unexpected[module] = struct{}{}
	}
	if len(unexpected) != 0 {
		names := make([]string, 0, len(unexpected))
		for module := range unexpected {
			names = append(names, module)
		}
		t.Fatalf("the engine gained modules outside the reviewed set: %s", strings.Join(names, ", "))
	}
}
