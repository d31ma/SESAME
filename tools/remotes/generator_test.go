package remotes_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d31ma/sesame/tools/remotes"
)

const probeFamilyTemplate = `{{.Family.ClassName}} {{.Family.Path}}
{{- range .Family.Methods}} {{.Verb.Pascal}} {{.Words.Camel}} {{.Path}} {{.Operation}} {{.Access}} [{{.Header}}] [{{.HeaderParameter.Camel}}] {{.HasBody}};{{end}}
`

const probeIndexTemplate = `{{range .Families}}{{.ClassName}} {{end}}
`

const probeManifest = `{
  "http_coverage": {
    "admin.bootstrap": {"category": "command_line_only", "reason": "local only"},
    "system.ping": {"category": "routed", "routes": ["POST /api/v1/system/ping"], "access": {"POST /api/v1/system/ping": "public"}},
    "system.metrics": {"category": "routed", "routes": ["POST /api/v1/system/metrics"], "access": {"POST /api/v1/system/metrics": "administrator"}},
    "authorize.decide": {"category": "routed", "routes": ["POST /api/v1/authorize/decide"], "access": {"POST /api/v1/authorize/decide": "signed_in"}},
    "scim.user_get": {"category": "routed", "routes": ["POST /api/v1/scim/user-get"], "access": {"POST /api/v1/scim/user-get": "public"}},
    "oidc_client.get": {"category": "routed", "routes": ["POST /api/v1/oidc-client/get"], "access": {"POST /api/v1/oidc-client/get": "administrator"}},
    "oidc.discovery": {"category": "standard_endpoint", "endpoint": "oidc.discovery", "routes": ["GET /oidc/openid-configuration"], "access": {"GET /oidc/openid-configuration": "public"}},
    "standards.dispatch": {"category": "standard_endpoint", "routes": ["GET /oidc/jwks", "GET /oidc/openid-configuration", "POST /oidc/token"], "access": {"GET /oidc/jwks": "public", "GET /oidc/openid-configuration": "public", "POST /oidc/token": "public"}}
  }
}`

func probeRoot(t *testing.T, manifest string, templates map[string]string) string {
	t.Helper()

	root := t.TempDir()
	writeProbeFile(t, filepath.Join(root, "api", "machine", "v1", "operations.json"), manifest)
	for name, content := range templates {
		writeProbeFile(t, filepath.Join(root, "tools", "remotes", "templates", filepath.FromSlash(name)), content)
	}
	return root
}

func writeProbeFile(t *testing.T, name string, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func probeTemplates() map[string]string {
	return map[string]string{
		"probe/server/remotes/Family.txt.tmpl": probeFamilyTemplate,
		"probe/INDEX.md.tmpl":                  probeIndexTemplate,
	}
}

func TestGeneratorRendersOneFilePerFamilyAndOneFilePerTemplate(t *testing.T) {
	t.Parallel()

	files, err := remotes.NewGenerator(probeRoot(t, probeManifest, probeTemplates())).Files()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	want := map[string]string{
		"probe/INDEX.md": "SesameAuthorizeClient SesameOidcClientClient SesameScimClient SesameStandardsClient SesameSystemClient \n",
		"probe/server/remotes/SesameAuthorizeClient.txt":  "SesameAuthorizeClient /api/v1/authorize Post decide /decide authorize.decide signed_in [Sesame-Session] [session] true;\n",
		"probe/server/remotes/SesameOidcClientClient.txt": "SesameOidcClientClient /api/v1/oidc-client Post get /get oidc_client.get administrator [Sesame-Session] [session] true;\n",
		"probe/server/remotes/SesameScimClient.txt":       "SesameScimClient /api/v1/scim Post userGet /user-get scim.user_get public [Authorization] [authorization] true;\n",
		"probe/server/remotes/SesameStandardsClient.txt":  "SesameStandardsClient /oidc Get jwks /jwks standards.dispatch public [] [] false; Get openidConfiguration /openid-configuration oidc.discovery public [] [] false;\n",
		"probe/server/remotes/SesameSystemClient.txt":     "SesameSystemClient /api/v1/system Post metrics /metrics system.metrics administrator [Sesame-Session] [session] true; Post ping /ping system.ping public [] [] true;\n",
	}
	if len(files) != len(want) {
		t.Errorf("generated %d files; want %d: %v", len(files), len(want), keys(files))
	}
	for name, content := range want {
		if got := string(files[name]); got != content {
			t.Errorf("%s:\n got %q\nwant %q", name, got, content)
		}
	}
}

func TestGeneratorRefusesARouteWithAnUnknownAccess(t *testing.T) {
	t.Parallel()

	manifest := `{"http_coverage": {"system.ping": {"category": "routed", "routes": ["POST /api/v1/system/ping"], "access": {}}}}`
	expectGeneratorFailure(t, manifest, probeTemplates(), "POST /api/v1/system/ping needs an access")
}

func TestGeneratorRefusesARouteMethodItCannotSend(t *testing.T) {
	t.Parallel()

	manifest := `{"http_coverage": {"system.ping": {"category": "routed", "routes": ["PUT /api/v1/system/ping"], "access": {"PUT /api/v1/system/ping": "public"}}}}`
	expectGeneratorFailure(t, manifest, probeTemplates(), "PUT /api/v1/system/ping needs an access")
}

func TestGeneratorRefusesARouteOutsideTheRouteConvention(t *testing.T) {
	t.Parallel()

	manifest := `{"http_coverage": {"system.ping": {"category": "routed", "routes": ["POST /api/v1/system/deep/ping"], "access": {"POST /api/v1/system/deep/ping": "public"}}}}`
	expectGeneratorFailure(t, manifest, probeTemplates(), "/api/v1/system/deep is neither")
}

func TestGeneratorRefusesAnOperationNameThatIsNotHyphenatedWords(t *testing.T) {
	t.Parallel()

	manifest := `{"http_coverage": {"system.ping": {"category": "routed", "routes": ["POST /api/v1/system/Ping_Now"], "access": {"POST /api/v1/system/Ping_Now": "public"}}}}`
	expectGeneratorFailure(t, manifest, probeTemplates(), `ends in "Ping_Now"`)
}

func TestGeneratorRefusesTwoMethodsWithTheSameName(t *testing.T) {
	t.Parallel()

	manifest := `{"http_coverage": {
	  "system.ping": {"category": "routed", "routes": ["POST /api/v1/system/ping"], "access": {"POST /api/v1/system/ping": "public"}},
	  "system.ping_read": {"category": "routed", "routes": ["GET /api/v1/system/ping"], "access": {"GET /api/v1/system/ping": "public"}}
	}}`
	expectGeneratorFailure(t, manifest, probeTemplates(), `SesameSystemClient would have two methods named "ping"`)
}

func TestGeneratorRefusesATemplateSetFileThatIsNotATemplate(t *testing.T) {
	t.Parallel()

	templates := probeTemplates()
	templates["probe/notes.txt"] = "not a template"
	expectGeneratorFailure(t, probeManifest, templates, "every file in a template set ends in .tmpl")
}

func TestGeneratorRefusesATemplateThatNamesAnUnknownField(t *testing.T) {
	t.Parallel()

	templates := probeTemplates()
	templates["probe/BROKEN.md.tmpl"] = "{{.Family.Nickname}}"
	expectGeneratorFailure(t, probeManifest, templates, "Nickname")
}

func TestGeneratorRefusesAMissingManifest(t *testing.T) {
	t.Parallel()

	_, err := remotes.NewGenerator(t.TempDir()).Files()
	if err == nil {
		t.Fatal("generate without operations.json succeeded")
	}
}

func TestWriteReplacesEachGeneratedLanguageFolder(t *testing.T) {
	t.Parallel()

	root := probeRoot(t, probeManifest, probeTemplates())
	output := filepath.Join(root, "remotes")
	stale := filepath.Join(output, "probe", "server", "remotes", "SesameRetiredClient.txt")
	kept := filepath.Join(output, "other", "KEEP.md")
	writeProbeFile(t, stale, "old")
	writeProbeFile(t, kept, "not generated")
	if err := remotes.NewGenerator(root).Write(output); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("the stale %s survived the write (err %v)", stale, err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Errorf("a folder that no template set owns was touched: %v", err)
	}
	written, err := os.ReadFile(filepath.Join(output, "probe", "INDEX.md"))
	if err != nil || !strings.HasPrefix(string(written), "SesameAuthorizeClient ") {
		t.Errorf("INDEX.md = %q, %v", written, err)
	}
}

func TestWriteChangesNothingWhenGenerationFails(t *testing.T) {
	t.Parallel()

	templates := probeTemplates()
	templates["probe/notes.txt"] = "not a template"
	root := probeRoot(t, probeManifest, templates)
	output := filepath.Join(root, "remotes")
	existing := filepath.Join(output, "probe", "INDEX.md")
	writeProbeFile(t, existing, "committed")
	if err := remotes.NewGenerator(root).Write(output); err == nil {
		t.Fatal("write with a broken template set succeeded")
	}
	content, err := os.ReadFile(existing)
	if err != nil || string(content) != "committed" {
		t.Errorf("a failed write changed %s: %q, %v", existing, content, err)
	}
}

func TestWordsSpellTheNameInEachLanguageStyle(t *testing.T) {
	t.Parallel()

	words := remotes.Words{"passkey", "list", "for", "principal"}
	cases := [][2]string{
		{words.Pascal(), "PasskeyListForPrincipal"},
		{words.Camel(), "passkeyListForPrincipal"},
		{words.Snake(), "passkey_list_for_principal"},
		{words.Kebab(), "passkey-list-for-principal"},
	}
	for _, testCase := range cases {
		if testCase[0] != testCase[1] {
			t.Errorf("got %q; want %q", testCase[0], testCase[1])
		}
	}
}

func expectGeneratorFailure(t *testing.T, manifest string, templates map[string]string, fragment string) {
	t.Helper()

	_, err := remotes.NewGenerator(probeRoot(t, manifest, templates)).Files()
	if err == nil || !strings.Contains(err.Error(), fragment) {
		t.Fatalf("error = %v; want one that contains %q", err, fragment)
	}
}

func keys(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	return names
}

func TestWordsSpellNoWordsAsAnEmptyName(t *testing.T) {
	t.Parallel()

	for _, got := range []string{remotes.Words{}.Camel(), remotes.Words{""}.Pascal(), remotes.Words{}.Snake()} {
		if got != "" {
			t.Errorf("got %q; want an empty name", got)
		}
	}
}
