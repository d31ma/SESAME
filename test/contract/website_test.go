package contract_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The marketing site quotes numbers about this repository, and a marketing
// site is exactly where a security project quietly starts overstating itself.
// These tests join website/client/shared/scripts/facts.js back to the sources
// it describes, so a claim on the website cannot drift away from the code the
// same way an undocumented operation cannot drift away from the manifest.
//
// They read the file as text rather than executing it: the site is JavaScript
// and this suite is Go, and a regular expression over a hand-maintained list
// is a smaller price than a JavaScript runtime in the test path.

func loadFacts(t *testing.T) (string, string) {
	t.Helper()

	root := repositoryRoot(t)
	path := filepath.Join(root, "website", "client", "shared", "scripts", "facts.js")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the website facts: %v", err)
	}
	return string(content), root
}

// TestWebsiteOperationCountMatchesTheManifest: the homepage advertises a
// number of protocol operations, and the manifest is what actually defines
// them.
func TestWebsiteOperationCountMatchesTheManifest(t *testing.T) {
	t.Parallel()

	facts, _ := loadFacts(t)
	loaded, _ := loadManifest(t)

	match := regexp.MustCompile(`OPERATION_COUNT = (\d+)`).FindStringSubmatch(facts)
	if match == nil {
		t.Fatal("the website facts declare no OPERATION_COUNT")
	}
	advertised, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("OPERATION_COUNT is not a number: %v", err)
	}
	if advertised != len(loaded.Operations) {
		t.Fatalf("the website advertises %d operations; the manifest defines %d",
			advertised, len(loaded.Operations))
	}
}

// TestWebsiteSDKListMatchesTheShippedClients: every language named on the site
// must be one a developer can actually download, and every shipped shim must
// be named — an omission understates the project, which is a bug too.
func TestWebsiteSDKListMatchesTheShippedClients(t *testing.T) {
	t.Parallel()

	facts, root := loadFacts(t)
	block := regexp.MustCompile(`(?s)SDK_LANGUAGES = \[(.*?)\]`).FindStringSubmatch(facts)
	if block == nil {
		t.Fatal("the website facts declare no SDK_LANGUAGES")
	}

	// The site spells languages for a reader; clients/ spells them for a file
	// system. This is the mapping between the two.
	directoryFor := map[string]string{
		"Go": "go", "Node.js": "node", "Python": "python", "Rust": "rust",
		"Java": "java", "Kotlin": "kotlin", "C#": "csharp", "PHP": "php",
		"Ruby": "ruby", "Dart": "dart",
	}

	advertised := map[string]bool{}
	for _, quoted := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(block[1], -1) {
		language := quoted[1]
		directory, known := directoryFor[language]
		if !known {
			t.Errorf("the website names SDK %q, which has no clients/ directory mapping", language)
			continue
		}
		if _, err := os.Stat(filepath.Join(root, "clients", directory)); err != nil {
			t.Errorf("the website names SDK %q, but clients/%s does not exist", language, directory)
			continue
		}
		advertised[directory] = true
	}

	entries, err := os.ReadDir(filepath.Join(root, "clients"))
	if err != nil {
		t.Fatalf("read clients: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !advertised[entry.Name()] {
			t.Errorf("clients/%s ships, but the website never mentions it", entry.Name())
		}
	}
}

// TestWebsiteMakesNoUnearnedSupportClaim guards the one thing a marketing site
// must never do here. Four claims are deliberately not made anywhere in the
// project, and the site is the surface most likely to make one by accident.
func TestWebsiteMakesNoUnearnedSupportClaim(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	directory := filepath.Join(root, "website", "client")

	// Each phrase is one a reader would take as a claim of certification,
	// production readiness, or proven interoperability.
	forbidden := []string{
		"openid certified",
		"openid certification passed",
		"production ready",
		"production-ready",
		"enterprise ready",
		"enterprise-grade",
		"battle tested",
		"battle-tested",
		"fully compliant",
		"certified implementation",
	}

	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		switch filepath.Ext(path) {
		case ".html", ".js", ".css":
		default:
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lowered := strings.ToLower(string(content))
		relative, _ := filepath.Rel(root, path)
		for _, phrase := range forbidden {
			if strings.Contains(lowered, phrase) {
				t.Errorf("%s claims %q, which SESAME has not earned", relative, phrase)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the website: %v", err)
	}
}

// TestWebsiteGuideSnippetsCallRealSDKMethods is the guard that makes the
// guides worth publishing.
//
// Their whole claim is that they are working call sequences rather than
// descriptions of one, and the cheapest way for that to become false is an
// SDK method being renamed while a snippet keeps the old name. Every
// `client.<method>(` in the guide snippets has to be defined by at least one
// shim that spells methods that way — the ten languages fall into three
// casing families, and a method resolves if any shim in its family has it.
func TestWebsiteGuideSnippetsCallRealSDKMethods(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	snippets, err := os.ReadFile(filepath.Join(root, "website", "client",
		"components", "code", "tabs", "tac.js"))
	if err != nil {
		t.Fatalf("read the guide snippets: %v", err)
	}

	read := func(parts ...string) string {
		content, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
		if err != nil {
			t.Fatalf("read %v: %v", parts, err)
		}
		return string(content)
	}
	// How each shim spells a method definition, grouped by the casing its
	// language uses. A PascalCase call could be Go or C#; a camelCase one
	// could be any of five.
	families := map[string][]struct {
		language   string
		source     string
		definition string
	}{
		"snake": {
			{"Python", read("clients", "python", "sesame.py"), "def %s("},
			{"Ruby", read("clients", "ruby", "sesame.rb"), "def %s("},
			{"Rust", read("clients", "rust", "sesame.rs"), "fn %s("},
		},
		"camel": {
			{"Node.js", read("clients", "node", "sesame.mjs"), "    %s = "},
			{"Java", read("clients", "java", "Sesame.java"), " %s("},
			{"Kotlin", read("clients", "kotlin", "Sesame.kt"), "fun %s("},
			{"PHP", read("clients", "php", "sesame.php"), "function %s("},
			{"Dart", read("clients", "dart", "sesame.dart"), "> %s("},
		},
		"pascal": {
			{"Go", read("clients", "go", "sesame", "client.go"), "func (c *Client) %s("},
			{"C#", read("clients", "csharp", "Sesame.cs"), " %s("},
		},
	}

	calls := regexp.MustCompile(`client\.([A-Za-z_][A-Za-z0-9_]*)\(`).
		FindAllStringSubmatch(string(snippets), -1)
	if len(calls) == 0 {
		t.Fatal("no client calls found in the guide snippets")
	}

	family := func(method string) string {
		switch {
		case strings.Contains(method, "_"):
			return "snake"
		case method[0] >= 'A' && method[0] <= 'Z':
			return "pascal"
		case strings.ToLower(method) != method:
			return "camel"
		default:
			// A single lowercase word — `authorize`, `decide`, `request` — is
			// spelled the same in every non-Pascal language.
			return "any"
		}
	}

	seen := map[string]bool{}
	for _, call := range calls {
		method := call[1]
		if seen[method] {
			continue
		}
		seen[method] = true

		wanted := family(method)
		found := false
		for name, shims := range families {
			if wanted != "any" && name != wanted {
				continue
			}
			for _, shim := range shims {
				if strings.Contains(shim.source, fmt.Sprintf(shim.definition, method)) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			t.Errorf("a guide calls client.%s(), which no %s-cased shim defines", method, wanted)
		}
	}
	t.Logf("resolved %d distinct SDK methods referenced by the guides", len(seen))
}

// TestWebsiteDocsNavIsWhole keeps the documentation map honest.
//
// The sidebar and the guide grid render from one shared list. That was not
// always true, and the two copies drifted: a guide the sidebar never showed,
// and a sidebar entry pointing at a renamed page. Both failures are invisible
// until a visitor finds them, so they are checked here instead.
//
// Two claims: every on-site route in the map resolves to a page that exists,
// and both surfaces still read from the map rather than from a local copy.
func TestWebsiteDocsNavIsWhole(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	navPath := filepath.Join(root, "website", "client", "shared", "scripts", "docs-nav.js")
	nav, err := os.ReadFile(navPath)
	if err != nil {
		t.Fatalf("read the docs map: %v", err)
	}

	routes := regexp.MustCompile(`href: '(/[^']*)'`).FindAllStringSubmatch(string(nav), -1)
	if len(routes) == 0 {
		t.Fatal("the docs map lists no on-site routes")
	}
	for _, route := range routes {
		relative := strings.TrimPrefix(route[1], "/")
		page := filepath.Join(root, "website", "client", "pages",
			filepath.FromSlash(relative), "tac.html")
		if _, err := os.Stat(page); err != nil {
			t.Errorf("the docs map links to %s, but %s does not exist",
				route[1], strings.TrimPrefix(page, root+"/"))
		}
	}
	t.Logf("checked %d on-site documentation routes", len(routes))

	// A surface that stopped importing the map would pass the check above
	// while showing something else entirely.
	for _, surface := range [][]string{
		{"website", "client", "components", "docs", "guides", "tac.js"},
		{"website", "client", "components", "docs", "sidebar", "tac.js"},
	} {
		source, err := os.ReadFile(filepath.Join(append([]string{root}, surface...)...))
		if err != nil {
			t.Fatalf("read %v: %v", surface, err)
		}
		if !strings.Contains(string(source), "shared/scripts/docs-nav.js") {
			t.Errorf("%s no longer renders from the shared documentation map",
				filepath.Join(surface...))
		}
	}
}

// TestWebsiteDocsPagesCarryTheSidebar. A docs page that forgot the shell is a
// dead end: no way forward except the browser's back button.
func TestWebsiteDocsPagesCarryTheSidebar(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	docs := filepath.Join(root, "website", "client", "pages", "docs")
	pages, err := filepath.Glob(filepath.Join(docs, "*", "tac.html"))
	if err != nil {
		t.Fatalf("list documentation pages: %v", err)
	}
	pages = append(pages, filepath.Join(docs, "tac.html"))
	if len(pages) < 2 {
		t.Fatalf("found %d documentation pages; the glob is wrong", len(pages))
	}

	for _, page := range pages {
		markup, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("read %s: %v", page, err)
		}
		for _, required := range []string{"<docs-sidebar />", `class="docs-shell`} {
			if !strings.Contains(string(markup), required) {
				t.Errorf("%s is missing %s", strings.TrimPrefix(page, root+"/"), required)
			}
		}
	}
	t.Logf("checked %d documentation pages for the sidebar shell", len(pages))
}

// TestWebsiteErrorReferenceMatchesTheEngine holds the published error
// reference to the codes the engine actually emits, in both directions.
//
// A documented code the engine never returns sends a developer chasing a
// branch that can never be taken. An emitted code the reference omits is
// worse: they meet it in production with nowhere to look it up. Both are
// failures here.
func TestWebsiteErrorReferenceMatchesTheEngine(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	page, err := os.ReadFile(filepath.Join(root, "website", "client", "pages",
		"docs", "errors", "tac.js"))
	if err != nil {
		t.Fatalf("read the error reference: %v", err)
	}
	documented := map[string]bool{}
	for _, match := range regexp.MustCompile(`code: '([a-z0-9_]+)'`).
		FindAllStringSubmatch(string(page), -1) {
		documented[match[1]] = true
	}

	// The engine's wire codes, read from the constants that define them.
	adapters, err := os.ReadDir(filepath.Join(root, "internal", "adapters", "machine"))
	if err != nil {
		t.Fatalf("read the machine adapter: %v", err)
	}
	emitted := map[string]bool{}
	constant := regexp.MustCompile(`\sError[A-Za-z0-9]*\s*=\s*"([a-z0-9_]+)"`)
	for _, entry := range adapters {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, "internal", "adapters", "machine", entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		for _, match := range constant.FindAllStringSubmatch(string(content), -1) {
			emitted[match[1]] = true
		}
	}
	if len(emitted) == 0 {
		t.Fatal("found no error-code constants in the machine adapter")
	}

	for code := range emitted {
		if !documented[code] {
			t.Errorf("the engine can return %q, which the error reference never documents", code)
		}
	}
	for code := range documented {
		// Decision reasons are not wire errors; they come from the
		// authorization package and are checked separately below.
		if strings.HasPrefix(code, "allow_") || strings.HasPrefix(code, "deny_") {
			continue
		}
		if !emitted[code] {
			t.Errorf("the error reference documents %q, which the engine never returns", code)
		}
	}

	// The decision reasons, from the constants that define those.
	authorization := filepath.Join(root, "internal", "application", "identity", "authorization.go")
	content, err := os.ReadFile(authorization)
	if err != nil {
		t.Fatalf("read the authorization reasons: %v", err)
	}
	reasons := regexp.MustCompile(`\sReason[A-Za-z0-9]*\s*=\s*"((?:allow|deny)_[a-z_]+)"`).
		FindAllStringSubmatch(string(content), -1)
	if len(reasons) == 0 {
		t.Fatal("found no decision-reason constants")
	}
	for _, match := range reasons {
		if !documented[match[1]] {
			t.Errorf("a decision can return %q, which the error reference never documents", match[1])
		}
	}
	t.Logf("checked %d wire codes and %d decision reasons", len(emitted), len(reasons))
}
