package contract_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/adapters/machine"
)

// The operation manifest is the one place the machine surface is written down.
// These three tests make it binding rather than decorative: it is checked
// against the engine that routes the operations, the documentation that
// describes them, and the SDKs that expose them. A manifest nothing checks is
// a promise, and this project does not ship promises as evidence.

type manifest struct {
	ProtocolVersion string              `json:"protocol_version"`
	Operations      []string            `json:"operations"`
	SDKGaps         map[string][]string `json:"sdk_gaps"`
}

func loadManifest(t *testing.T) (manifest, string) {
	t.Helper()

	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "api", "machine", "v1", "operations.json"))
	if err != nil {
		t.Fatalf("read operation manifest: %v", err)
	}
	var loaded manifest
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("decode operation manifest: %v", err)
	}
	if len(loaded.Operations) == 0 {
		t.Fatal("the operation manifest is empty")
	}
	return loaded, root
}

// TestManifestMatchesTheEngineDispatchTable parses the processor's own switch
// rather than trusting a list beside it. An operation the engine routes but
// the manifest omits would ship undocumented and unexposed; one the manifest
// claims but the engine does not route would be a lie in a published file.
func TestManifestMatchesTheEngineDispatchTable(t *testing.T) {
	t.Parallel()

	loaded, root := loadManifest(t)

	// The whole package, not just processor.go: the dispatch table is spread
	// across files as slices add their own route maps, and reading only one
	// file would silently report a slice's operations as unrouted.
	fileSet := token.NewFileSet()
	packageDir := filepath.Join(root, "internal", "adapters", "machine")
	packages, err := parser.ParseDir(fileSet, packageDir, nil, 0)
	if err != nil {
		t.Fatalf("parse the machine package: %v", err)
	}

	routed := map[string]struct{}{}
	collect := func(node ast.Node) bool {
		// The dispatch table is the map literal returned by routes(). Reading
		// it from the AST rather than calling it keeps this check independent
		// of the engine's own view of what it routes.
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		mapType, ok := literal.Type.(*ast.MapType)
		if !ok {
			return true
		}
		value, ok := mapType.Value.(*ast.Ident)
		if !ok || value.Name != "handlerFunc" {
			return true
		}
		for _, element := range literal.Elts {
			pair, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := pair.Key.(*ast.BasicLit)
			if !ok || key.Kind != token.STRING {
				continue
			}
			operation, err := strconv.Unquote(key.Value)
			if err != nil {
				continue
			}
			routed[operation] = struct{}{}
		}
		return true
	}
	for name, pkg := range packages {
		if strings.HasSuffix(name, "_test") {
			continue
		}
		for _, file := range pkg.Files {
			ast.Inspect(file, collect)
		}
	}
	if len(routed) == 0 {
		t.Fatal("no dispatch table was found in the machine processor")
	}

	declared := map[string]struct{}{}
	for _, operation := range loaded.Operations {
		declared[operation] = struct{}{}
	}

	var missing, extra []string
	for operation := range routed {
		if _, ok := declared[operation]; !ok {
			missing = append(missing, operation)
		}
	}
	for operation := range declared {
		if _, ok := routed[operation]; !ok {
			extra = append(extra, operation)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) != 0 {
		t.Errorf("the engine routes operations the manifest omits: %s", strings.Join(missing, ", "))
	}
	if len(extra) != 0 {
		t.Errorf("the manifest claims operations the engine does not route: %s", strings.Join(extra, ", "))
	}

	// The list the engine reports at runtime through system.version is the
	// third place this set is written down. All three must agree, or a client
	// that trusts the reported list would be told about an operation nobody
	// routes — or not told about one that exists.
	reported := map[string]struct{}{}
	for _, operation := range machine.Operations {
		reported[operation] = struct{}{}
	}
	if len(reported) != len(machine.Operations) {
		t.Error("machine.Operations contains a duplicate")
	}
	if !sort.StringsAreSorted(machine.Operations) {
		t.Error("machine.Operations is not sorted; clients may compare it directly")
	}
	var unreported, overreported []string
	for operation := range routed {
		if _, ok := reported[operation]; !ok {
			unreported = append(unreported, operation)
		}
	}
	for operation := range reported {
		if _, ok := routed[operation]; !ok {
			overreported = append(overreported, operation)
		}
	}
	sort.Strings(unreported)
	sort.Strings(overreported)
	if len(unreported) != 0 {
		t.Errorf("the engine routes operations system.version does not report: %s",
			strings.Join(unreported, ", "))
	}
	if len(overreported) != 0 {
		t.Errorf("system.version reports operations the engine does not route: %s",
			strings.Join(overreported, ", "))
	}
}

// TestEveryOperationIsDocumented keeps the protocol reference honest. A
// shipped operation nobody wrote down is one integrators discover by reading
// the source.
func TestEveryOperationIsDocumented(t *testing.T) {
	t.Parallel()

	loaded, root := loadManifest(t)
	reference, err := os.ReadFile(filepath.Join(root, "api", "machine", "v1", "README.md"))
	if err != nil {
		t.Fatalf("read the protocol reference: %v", err)
	}
	documentation := string(reference)

	var undocumented []string
	for _, operation := range loaded.Operations {
		// The reference lists every operation in a table cell as `name`.
		if !strings.Contains(documentation, "`"+operation+"`") {
			undocumented = append(undocumented, operation)
		}
	}
	if len(undocumented) != 0 {
		sort.Strings(undocumented)
		t.Fatalf("operations missing from api/machine/v1/README.md: %s", strings.Join(undocumented, ", "))
	}
}

// TestSDKCoverageMatchesTheDeclaredGaps measures what each shim actually
// exposes and compares it against what the manifest admits.
//
// A gap is not a defect: every SDK can reach every operation through its
// generic request escape hatch, and a typed method is a convenience. What
// would be a defect is a gap nobody wrote down, or a closed gap the manifest
// still advertises. Both fail here, which turns SDK parity into a list that
// can only shrink deliberately.
func TestSDKCoverageMatchesTheDeclaredGaps(t *testing.T) {
	t.Parallel()

	loaded, root := loadManifest(t)
	extensions := map[string]struct{}{
		".go": {}, ".js": {}, ".mjs": {}, ".ts": {}, ".py": {}, ".rs": {},
		".java": {}, ".kt": {}, ".cs": {}, ".php": {}, ".rb": {}, ".dart": {},
	}

	for sdk, declared := range loaded.SDKGaps {
		directory := filepath.Join(root, "clients", sdk)
		if _, err := os.Stat(directory); err != nil {
			t.Errorf("the manifest names SDK %q, which does not exist", sdk)
			continue
		}

		var builder strings.Builder
		err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// Build output is not SDK source. Reading it would let a
			// generated file satisfy a coverage claim the hand-written
			// client does not actually make.
			if entry.IsDir() {
				switch entry.Name() {
				case "obj", "bin", "target", "node_modules", "build", ".dart_tool", "__pycache__":
					return filepath.SkipDir
				}
				return nil
			}
			if _, ok := extensions[filepath.Ext(path)]; !ok {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			builder.Write(content)
			builder.WriteString("\n")
			return nil
		})
		if err != nil {
			t.Fatalf("scan the %s SDK: %v", sdk, err)
		}
		source := builder.String()

		measured := map[string]struct{}{}
		for _, operation := range loaded.Operations {
			if !strings.Contains(source, `"`+operation+`"`) &&
				!strings.Contains(source, `'`+operation+`'`) {
				measured[operation] = struct{}{}
			}
		}
		declaredSet := map[string]struct{}{}
		for _, operation := range declared {
			declaredSet[operation] = struct{}{}
		}

		var undeclared, stale []string
		for operation := range measured {
			if _, ok := declaredSet[operation]; !ok {
				undeclared = append(undeclared, operation)
			}
		}
		for operation := range declaredSet {
			if _, ok := measured[operation]; !ok {
				stale = append(stale, operation)
			}
		}
		sort.Strings(undeclared)
		sort.Strings(stale)
		if len(undeclared) != 0 {
			t.Errorf("the %s SDK is missing operations the manifest does not admit: %s",
				sdk, strings.Join(undeclared, ", "))
		}
		if len(stale) != 0 {
			t.Errorf("the %s SDK now covers operations the manifest still lists as gaps; "+
				"remove them from api/machine/v1/operations.json: %s", sdk, strings.Join(stale, ", "))
		}
	}

	// Every shim must be accounted for, so a new SDK cannot arrive with no
	// declared surface at all.
	entries, err := os.ReadDir(filepath.Join(root, "clients"))
	if err != nil {
		t.Fatalf("list clients: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, ok := loaded.SDKGaps[entry.Name()]; !ok {
			t.Errorf("SDK %q has no entry in the manifest's sdk_gaps", entry.Name())
		}
	}
}

// TestEverySDKCanExpressASessionDecision guards the parity gap that let seven
// shims ship without it.
//
// The engine accepts a session in place of a principal on authorize.decide,
// which is how a step-up condition is enforced. Python, Node and Go could
// express that because their decide() takes a request object; the other seven
// took positional arguments and silently could not, so the only route was the
// raw request() escape hatch. A capability the engine has and a shim cannot
// reach is the same kind of drift as a missing operation.
func TestEverySDKCanExpressASessionDecision(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)

	// Each shim either takes a request object on decide (so a session is just
	// another key) or carries a named session variant.
	shims := map[string][]string{
		filepath.Join("clients", "python", "sesame.py"):       {"def decide(self, request"},
		filepath.Join("clients", "node", "sesame.mjs"):        {"decide = (request"},
		filepath.Join("clients", "go", "sesame", "client.go"): {"SessionID     string"},
		filepath.Join("clients", "ruby", "sesame.rb"):         {"def decide_for_session("},
		filepath.Join("clients", "php", "sesame.php"):         {"function decideForSession("},
		filepath.Join("clients", "java", "Sesame.java"):       {"Object decideForSession("},
		filepath.Join("clients", "kotlin", "Sesame.kt"):       {"fun decideForSession("},
		filepath.Join("clients", "csharp", "Sesame.cs"):       {"JsonElement DecideForSession("},
		filepath.Join("clients", "dart", "sesame.dart"):       {"decideForSession("},
		filepath.Join("clients", "rust", "sesame.rs"):         {"fn decide_for_session("},
	}

	entries, err := os.ReadDir(filepath.Join(root, "clients"))
	if err != nil {
		t.Fatalf("read clients: %v", err)
	}
	shipped := 0
	for _, entry := range entries {
		if entry.IsDir() {
			shipped++
		}
	}
	if len(shims) != shipped {
		t.Fatalf("this test covers %d shims; clients/ ships %d", len(shims), shipped)
	}

	for path, wanted := range shims {
		content, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		found := false
		for _, marker := range wanted {
			if strings.Contains(string(content), marker) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s cannot express a session-based decision; the engine accepts one", path)
		}
	}
}
