package contract_test

import (
	"encoding/json"
	"go/ast"
	"go/build"
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
// These tests make it binding rather than decorative: it is checked against
// the engine that routes the operations, the documentation that describes
// them, and the Yon controllers that expose them over HTTP. A manifest nothing
// checks is a promise, and this project does not ship promises as evidence.

type manifest struct {
	ProtocolVersion string                       `json:"protocol_version"`
	Operations      []string                     `json:"operations"`
	HTTPCoverage    map[string]operationCoverage `json:"http_coverage"`
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
	buildPackage, err := build.Default.ImportDir(packageDir, 0)
	if err != nil {
		t.Fatalf("resolve the machine package: %v", err)
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
	files := append(append([]string{}, buildPackage.GoFiles...), buildPackage.CgoFiles...)
	for _, name := range files {
		file, err := parser.ParseFile(fileSet, filepath.Join(packageDir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse machine package file %s: %v", name, err)
		}
		ast.Inspect(file, collect)
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
