package contract_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStandardsRequestFieldsStayAlignedAcrossEngineAndGoSDK(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	engine := jsonFieldsOf(t,
		filepath.Join(root, "internal", "adapters", "machine", "standards_ops.go"),
		"type StandardsRequest struct {")
	sdk := jsonFieldsOf(t,
		filepath.Join(root, "clients", "go", "sesame", "client.go"),
		"type StandardsRequest struct {")
	if !reflect.DeepEqual(engine, sdk) {
		t.Fatalf("standards request fields disagree.\n  engine: %v\n  Go SDK: %v", engine, sdk)
	}
}

func TestStandardsSchemaNamesTheCompleteClosedEndpointSet(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "api", "standards", "v1", "host-adapter.schema.json"))
	if err != nil {
		t.Fatalf("read host-adapter schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode host-adapter schema: %v", err)
	}
	text := string(raw)
	for _, endpoint := range []string{
		"oidc.authorization",
		"oidc.discovery",
		"oidc.introspection",
		"oidc.jwks",
		"oidc.logout",
		"oidc.revocation",
		"oidc.token",
	} {
		if strings.Count(text, `"`+endpoint+`"`) != 1 {
			t.Errorf("schema occurrence count for %s is not one", endpoint)
		}
	}
}

func TestHostServerDelegatesStandardEndpointSemanticsToTheEngine(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	oidcSource, err := os.ReadFile(filepath.Join(root, "examples", "hostserver", "oidc.go"))
	if err != nil {
		t.Fatalf("read hostserver OIDC routes: %v", err)
	}
	translator, err := os.ReadFile(filepath.Join(root, "examples", "hostserver", "standards.go"))
	if err != nil {
		t.Fatalf("read hostserver standards translator: %v", err)
	}
	combined := string(oidcSource) + string(translator)
	if !strings.Contains(combined, ".StandardsDispatch(") {
		t.Fatal("hostserver does not call the framework-neutral dispatch contract")
	}
	for _, forbidden := range []string{
		".Authorize(",
		".Discovery(",
		".Introspect(",
		".Logout(",
		".Revoke(",
		".SigningKeys(",
		".TokenExchange(",
	} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("hostserver still implements a standard endpoint through %s", forbidden)
		}
	}
}
