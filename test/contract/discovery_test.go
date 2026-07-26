package contract_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestDiscoveryEndpointFieldsReachTheEngine guards a whole-feature outage that
// every existing drift test missed.
//
// The manifest tests check operation *names*. They cannot see that a
// parameter the SDK sends is one the engine's strict decoder refuses — and
// `end_session_endpoint` was exactly that: the domain advertised it, the Go
// SDK offered a typed field for it, and the machine handler had no such field.
// A host that named its logout route did not get a document missing one entry;
// it got the entire discovery call refused, so RP-initiated logout was
// undiscoverable in every deployment.
//
// This compares the two field sets directly. They are the same wire object and
// have no business disagreeing.
func TestDiscoveryEndpointFieldsReachTheEngine(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	sdk := jsonFieldsOf(t, filepath.Join(root, "clients", "go", "sesame", "client.go"),
		"type DiscoveryEndpoints struct {")
	engine := jsonFieldsOf(t, filepath.Join(root, "internal", "adapters", "machine", "processor.go"),
		"func (p *Processor) handleDiscovery(request Request) Response {")

	if len(sdk) == 0 || len(engine) == 0 {
		t.Fatalf("found %d SDK fields and %d engine fields; the anchors moved",
			len(sdk), len(engine))
	}
	if !reflect.DeepEqual(sdk, engine) {
		t.Errorf("the discovery parameter sets disagree.\n  SDK sends: %v\n  engine accepts: %v\n"+
			"a field the SDK sends and the engine does not accept fails the whole call",
			sdk, engine)
	}

	// And the domain has to be able to carry every one of them onward.
	domain := jsonFieldsOf(t, filepath.Join(root, "internal", "domain", "oidc", "discovery.go"),
		"type Endpoints struct {")
	for _, field := range sdk {
		if !contains(domain, field) {
			t.Errorf("the engine accepts %q but the domain's Endpoints cannot carry it", field)
		}
	}
}

// jsonFieldsOf collects the json tag names of the first struct following an
// anchor, which covers both a named type and an inline parameter struct.
func jsonFieldsOf(t *testing.T, path, anchor string) []string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	body := string(content)
	start := strings.Index(body, anchor)
	if start < 0 {
		t.Fatalf("%s no longer contains %q", filepath.Base(path), anchor)
	}
	body = body[start+len(anchor):]
	// Inside a function the struct is a local declaration, so skip forward to
	// it before bounding — the first closing brace after a func signature
	// belongs to an early-return guard, not to the parameters.
	if inline := strings.Index(body, "var parameters struct {"); inline >= 0 && inline < 400 {
		body = body[inline+len("var parameters struct {"):]
		if end := strings.Index(body, "\n\t}\n"); end >= 0 {
			body = body[:end]
		}
	} else if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}

	var fields []string
	for _, line := range strings.Split(body, "\n") {
		open := strings.Index(line, "`json:\"")
		if open < 0 {
			continue
		}
		rest := line[open+len("`json:\""):]
		close := strings.Index(rest, "\"")
		if close < 0 {
			continue
		}
		name, _, _ := strings.Cut(rest[:close], ",")
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	return fields
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// TestDiscoveryManifestDocumentsEverySDKField keeps the published protocol
// reference in step with what the operation actually accepts.
func TestDiscoveryManifestDocumentsEverySDKField(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	reference, err := os.ReadFile(filepath.Join(root, "api", "machine", "v1", "README.md"))
	if err != nil {
		t.Fatalf("read the protocol reference: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join(root, "api", "machine", "v1", "operations.json"))
	if err != nil {
		t.Fatalf("read the manifest: %v", err)
	}
	var operations []string
	if err := json.Unmarshal(manifest, &operations); err != nil {
		// The manifest may be an object; the operation list is what matters.
		var wrapper struct {
			Operations []string `json:"operations"`
		}
		if err := json.Unmarshal(manifest, &wrapper); err != nil {
			t.Fatalf("decode the manifest: %v", err)
		}
		operations = wrapper.Operations
	}
	if !contains(operations, "oidc.discovery") {
		t.Fatal("the manifest no longer lists oidc.discovery")
	}
	if !strings.Contains(string(reference), "oidc.discovery") {
		t.Error("the protocol reference does not document oidc.discovery")
	}
}
