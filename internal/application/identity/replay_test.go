package identity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryProjectionIsReachableFromReplay is a structural guard on the
// replay table.
//
// It exists because of a real regression: converting the replay switch to a
// map dropped the two group-membership events, because they shared one
// multi-value `case` arm that a mechanical extraction did not match. Nothing
// failed to compile. The only symptom was a projection that silently stopped
// being applied, and the one test that happened to replay a membership change
// caught it.
//
// An apply function that no event type routes to is dead code at best and a
// forgotten projection at worst, and a forgotten projection means a restart
// quietly loses security state.
func TestEveryProjectionIsReachableFromReplay(t *testing.T) {
	t.Parallel()

	defined := projectionFunctions(t)
	if len(defined) < 40 {
		t.Fatalf("found only %d apply functions; the scan is not working", len(defined))
	}

	for name := range defined {
		if _, routed := routedProjections(t)[name]; !routed {
			t.Errorf("%s projects an event but no type in replayHandlers routes to it", name)
		}
	}
}

// projectionFunctions collects every apply* method on Service.
func projectionFunctions(t *testing.T) map[string]struct{} {
	t.Helper()

	found := map[string]struct{}{}
	for _, file := range packageFiles(t) {
		for _, declaration := range file.Decls {
			declared, ok := declaration.(*ast.FuncDecl)
			if !ok || declared.Recv == nil {
				continue
			}
			if strings.HasPrefix(declared.Name.Name, "apply") {
				found[declared.Name.Name] = struct{}{}
			}
		}
	}
	return found
}

// routedProjections collects the functions named as values in the
// replayHandlers table, and only those.
//
// Scanning the whole package for apply* references would be vacuous: every
// projection is also called directly by the command that appends its event,
// so it would always appear to be routed. The first version of this test made
// exactly that mistake and passed while the bug it was written for was
// present.
func routedProjections(t *testing.T) map[string]struct{} {
	t.Helper()

	found := map[string]struct{}{}
	for _, file := range packageFiles(t) {
		ast.Inspect(file, func(node ast.Node) bool {
			spec, ok := node.(*ast.ValueSpec)
			if !ok || len(spec.Names) == 0 || spec.Names[0].Name != "replayHandlers" {
				return true
			}
			for _, value := range spec.Values {
				collectSelectorNames(value, found)
			}
			return false
		})
	}
	return found
}

// collectSelectorNames reads the method names out of the table's values.
func collectSelectorNames(node ast.Node, into map[string]struct{}) {
	ast.Inspect(node, func(inner ast.Node) bool {
		if selector, ok := inner.(*ast.SelectorExpr); ok {
			into[selector.Sel.Name] = struct{}{}
		}
		return true
	})
}

func packageFiles(t *testing.T) []*ast.File {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	fileSet := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, parsed)
	}
	return files
}
