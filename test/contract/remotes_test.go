package contract_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/d31ma/sesame/tools/remotes"
)

const (
	remotesDirectory        = "remotes"
	remotesRegenerate       = "go run ./tools/remotes/generate"
	remoteReadme            = "README.md"
	remoteSessionHeader     = "Sesame-Session"
	remoteBearerHeader      = "Authorization"
	remoteProvisioningRoute = "/api/v1/scim/"
	remoteSameHostLanguage  = "rust"
	remoteSameHostNotice    = "**Same-host / development only:"
	remoteSameHostRule      = "sesame.origin must be http on localhost, 127.0.0.1 or [::1]: this Rust transport has no TLS"
)

var (
	remoteTemplateFolder    = filepath.Join("tools", "remotes", "templates")
	remoteBaselineLanguages = []string{"go", "typescript"}
	remoteClientPath        = regexp.MustCompile(`(?i)http_?client\(\s*\{\s*"path"\s*:\s*"(/[^"]*)"`)
	remoteRequestMarker     = regexp.MustCompile(`(?i)(get|post|put|patch|delete)_?request\(\s*"(/[^"]*)"\s*\)`)
	remoteHeaderMarker      = regexp.MustCompile(`(?i)request_?header\(\s*"([^"]+)"\s*\)`)
	remoteRoleFiles         = []string{"server/setups/SesameSetup", "server/helpers/SesameTransportHelper"}
	remoteRemoteFolder      = filepath.Join("server", "remotes")
	remoteMissingHeader     = ""
	remoteRequiredHeader    = map[string]string{
		accessSignedIn:      remoteSessionHeader,
		accessAdministrator: remoteSessionHeader,
	}
)

type remoteMethod struct {
	file   string
	header string
}

func TestCommittedRemotesMatchTheGenerator(t *testing.T) {
	t.Parallel()

	_, root := loadManifest(t)
	generated, err := remotes.NewGenerator(root).Files()
	if err != nil {
		t.Fatalf("generate the remotes: %v", err)
	}
	committed := committedRemoteFiles(t, filepath.Join(root, remotesDirectory))
	for name, content := range generated {
		existing, found := committed[name]
		if !found {
			t.Errorf("remotes/%s is generated but not committed; run %s", name, remotesRegenerate)
			continue
		}
		if !bytes.Equal(existing, content) {
			t.Errorf("remotes/%s differs from the generator's output; run %s", name, remotesRegenerate)
		}
	}
	for name := range committed {
		if _, found := generated[name]; !found {
			t.Errorf("remotes/%s is committed but the generator does not write it; run %s", name, remotesRegenerate)
		}
	}
}

func TestRemoteLanguagesAreTheTemplateFolders(t *testing.T) {
	t.Parallel()

	_, root := loadManifest(t)
	languages := remoteLanguages(t, root)
	for _, required := range remoteBaselineLanguages {
		if !slices.Contains(languages, required) {
			t.Errorf("tools/remotes/templates has no %s folder; found %v", required, languages)
		}
	}
	for _, language := range languages {
		readme := filepath.Join(root, remotesDirectory, language, remoteReadme)
		if _, err := os.Stat(readme); err != nil {
			t.Errorf("remotes/%s needs a %s: %v", language, remoteReadme, err)
		}
	}
}

func TestTheRustRemotesStaySameHostOnly(t *testing.T) {
	t.Parallel()

	_, root := loadManifest(t)
	folder := filepath.Join(root, remotesDirectory, remoteSameHostLanguage)
	readme, err := os.ReadFile(filepath.Join(folder, remoteReadme))
	if err != nil {
		t.Fatalf("read the Rust remotes README: %v", err)
	}
	if !strings.HasPrefix(strings.SplitN(string(readme), "\n\n", 3)[1], remoteSameHostNotice) {
		t.Errorf("remotes/%s/%s must open with %q", remoteSameHostLanguage, remoteReadme, remoteSameHostNotice)
	}
	helper, err := os.ReadFile(filepath.Join(folder, "server", "helpers", "SesameTransportHelper.rs"))
	if err != nil {
		t.Fatalf("read the Rust transport helper: %v", err)
	}
	if !strings.Contains(string(helper), remoteSameHostRule) || strings.Contains(string(helper), "https://") {
		t.Errorf("the Rust transport helper must refuse every origin except loopback http")
	}
}

func TestEveryLanguageShipsTheSetupAndTheTransportHelper(t *testing.T) {
	t.Parallel()

	_, root := loadManifest(t)
	for _, language := range remoteLanguages(t, root) {
		for _, role := range remoteRoleFiles {
			matches, err := filepath.Glob(filepath.Join(root, remotesDirectory, language, filepath.FromSlash(role)+".*"))
			if err != nil || len(matches) != 1 {
				t.Errorf("remotes/%s needs exactly one %s file, found %d", language, role, len(matches))
			}
		}
	}
}

func TestEveryRoutedRouteHasExactlyOneRemoteMethodPerLanguage(t *testing.T) {
	t.Parallel()

	loaded, root := loadManifest(t)
	access := routeAccessFromManifest(loaded)
	for _, language := range remoteLanguages(t, root) {
		methods := remoteMethods(t, filepath.Join(root, remotesDirectory, language, remoteRemoteFolder))
		for operation, coverage := range loaded.HTTPCoverage {
			if coverage.Category != coverageRouted {
				continue
			}
			for _, route := range coverage.Routes {
				if count := len(methods[route]); count != 1 {
					t.Errorf("%s: %s (%s) has %d remote methods; want exactly 1", language, route, operation, count)
				}
			}
		}
		for route, found := range methods {
			level, exists := access[route]
			if !exists {
				t.Errorf("%s: %s names %s, which operations.json does not route", language, found[0].file, route)
				continue
			}
			for _, method := range found {
				if want := remoteHeaderFor(route, level); method.header != want {
					t.Errorf("%s: %s %s sends header %q; want %q", language, method.file, route, method.header, want)
				}
			}
		}
	}
}

func TestRemoteHeadersFollowTheRouteAccess(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		route  string
		access string
		want   string
	}{
		"public":                {"POST /api/v1/system/ping", accessPublic, remoteMissingHeader},
		"signed in":             {"POST /api/v1/authorize/decide", accessSignedIn, remoteSessionHeader},
		"administrator":         {"POST /api/v1/principal/get", accessAdministrator, remoteSessionHeader},
		"provisioning":          {"POST /api/v1/scim/user-get", accessPublic, remoteBearerHeader},
		"provisioning by admin": {"POST /api/v1/scim/client-register", accessAdministrator, remoteSessionHeader},
		"standard endpoint":     {"GET /oidc/jwks", accessPublic, remoteMissingHeader},
	}
	for name, testCase := range cases {
		if got := remoteHeaderFor(testCase.route, testCase.access); got != testCase.want {
			t.Errorf("%s: header %q; want %q", name, got, testCase.want)
		}
	}
}

func remoteLanguages(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(filepath.Join(root, remoteTemplateFolder))
	if err != nil {
		t.Fatalf("list the remote template languages: %v", err)
	}
	languages := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			languages = append(languages, entry.Name())
		}
	}
	if len(languages) == 0 {
		t.Fatalf("%s holds no language folders", remoteTemplateFolder)
	}
	return languages
}

func remoteHeaderFor(route string, access string) string {
	if header, found := remoteRequiredHeader[access]; found {
		return header
	}
	if strings.Contains(route, remoteProvisioningRoute) {
		return remoteBearerHeader
	}
	return remoteMissingHeader
}

func routeAccessFromManifest(loaded manifest) map[string]string {
	access := map[string]string{}
	for _, coverage := range loaded.HTTPCoverage {
		if !coverage.mayBeRouted() {
			continue
		}
		for route, level := range coverage.Access {
			access[route] = level
		}
	}
	return access
}

func remoteMethods(t *testing.T, folder string) map[string][]remoteMethod {
	t.Helper()

	names, err := filepath.Glob(filepath.Join(folder, "*"))
	if err != nil || len(names) == 0 {
		t.Fatalf("list the remotes in %s: %v", folder, err)
	}
	sort.Strings(names)
	methods := map[string][]remoteMethod{}
	for _, name := range names {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		collectRemoteMethods(t, filepath.Base(name), string(content), methods)
	}
	return methods
}

func collectRemoteMethods(t *testing.T, file string, source string, methods map[string][]remoteMethod) {
	t.Helper()

	client := remoteClientPath.FindStringSubmatch(source)
	if client == nil {
		t.Errorf("%s has no HTTPClient with a \"path\" option", file)
		return
	}
	markers := remoteRequestMarker.FindAllStringSubmatchIndex(source, -1)
	for index, marker := range markers {
		end := len(source)
		if index+1 < len(markers) {
			end = markers[index+1][0]
		}
		verb := strings.ToUpper(source[marker[2]:marker[3]])
		route := verb + " " + client[1] + source[marker[4]:marker[5]]
		header := remoteHeaderMarker.FindStringSubmatch(source[marker[1]:end])
		method := remoteMethod{file: file}
		if header != nil {
			method.header = header[1]
		}
		methods[route] = append(methods[route], method)
	}
}

func committedRemoteFiles(t *testing.T, folder string) map[string][]byte {
	t.Helper()

	files := map[string][]byte{}
	err := filepath.WalkDir(folder, func(path string, entry fs.DirEntry, walkError error) error {
		if walkError != nil || entry.IsDir() {
			return walkError
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(folder, path)
		files[filepath.ToSlash(relative)] = content
		return err
	})
	if err != nil {
		t.Fatalf("read the committed remotes: %v", err)
	}
	return files
}
