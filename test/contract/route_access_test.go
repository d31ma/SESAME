package contract_test

import (
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var accessAnnotation = regexp.MustCompile(`^// @(Public|SignedIn|Allow\(([^)]*)\))\s*$`)

const (
	accessPublic          = "public"
	accessSignedIn        = "signed_in"
	accessAdministrator   = "administrator"
	publicAnnotation      = "Public"
	signedInAnnotation    = "SignedIn"
	administratorRole     = "Administrator"
	accessNamesDescribed  = "public, signed_in, administrator"
	controllersDirectory  = "controllers"
	serverDirectory       = "app/server"
	controllerFileMode    = 0o600
	controllerDirectories = 0o700
)

type declaredAccessTable map[string][]string

func loadDeclaredAccess(t *testing.T, root string) declaredAccessTable {
	t.Helper()

	source := parseControllers(t, filepath.Join(root, filepath.FromSlash(serverDirectory), controllersDirectory))
	table := declaredAccessTable{}
	for receiver, methods := range source.methods {
		prefix, isController := source.prefixes[receiver]
		if !isController {
			continue
		}
		for _, method := range methods {
			route, isRoute := routeOf(prefix, method)
			if !isRoute {
				continue
			}
			declared := declaredAccess(method.Doc)
			if len(declared) == 0 {
				declared = declaredAccess(source.annotations[receiver])
			}
			table[route] = declared
		}
	}
	if len(table) == 0 {
		t.Fatal("no Yon routes were found in app/server/controllers")
	}
	return table
}

func declaredAccess(comments *ast.CommentGroup) []string {
	if comments == nil {
		return nil
	}
	var declared []string
	for _, comment := range comments.List {
		if match := accessAnnotation.FindStringSubmatch(comment.Text); match != nil {
			declared = append(declared, accessName(match[1], match[2]))
		}
	}
	return declared
}

func accessName(annotationName string, roles string) string {
	switch annotationName {
	case publicAnnotation:
		return accessPublic
	case signedInAnnotation:
		return accessSignedIn
	}
	if strings.TrimSpace(roles) == administratorRole {
		return accessAdministrator
	}
	return "allow(" + roles + ")"
}

func isKnownAccess(access string) bool {
	switch access {
	case accessPublic, accessSignedIn, accessAdministrator:
		return true
	}
	return false
}

func routeAccessProblems(coverages map[string]operationCoverage, declared declaredAccessTable) []string {
	var problems []string
	recorded := map[string]bool{}
	for operation, coverage := range coverages {
		problems = append(problems, coverageAccessProblems(operation, coverage, declared)...)
		for route := range coverage.Access {
			recorded[route] = true
		}
	}
	for route, accesses := range declared {
		if len(accesses) != 1 {
			problems = append(problems, fmt.Sprintf("%s declares %d access annotations %v; want exactly one", route, len(accesses), accesses))
		}
		if !recorded[route] {
			problems = append(problems, fmt.Sprintf("%s has no recorded access in http_coverage", route))
		}
	}
	sort.Strings(problems)
	return problems
}

func coverageAccessProblems(operation string, coverage operationCoverage, declared declaredAccessTable) []string {
	var problems []string
	for _, route := range coverage.Routes {
		access, isRecorded := coverage.Access[route]
		if !isRecorded {
			problems = append(problems, fmt.Sprintf("%s lists %s without recording its access", operation, route))
			continue
		}
		if !isKnownAccess(access) {
			problems = append(problems, fmt.Sprintf("%s records %s as %q; want one of: %s", operation, route, access, accessNamesDescribed))
		}
		if controller := declared[route]; len(controller) == 1 && controller[0] != access {
			problems = append(problems, fmt.Sprintf("%s records %s as %s, but its controller declares %s", operation, route, access, controller[0]))
		}
	}
	for route := range coverage.Access {
		if !coverage.lists(route) {
			problems = append(problems, fmt.Sprintf("%s records access for %s, which it does not list", operation, route))
		}
	}
	return problems
}

func TestRecordedRouteAccessMatchesTheControllers(t *testing.T) {
	t.Parallel()

	loaded, root := loadManifest(t)
	for _, problem := range routeAccessProblems(loaded.HTTPCoverage, loadDeclaredAccess(t, root)) {
		t.Error(problem)
	}
}

func TestDeclaredAccessPrefersTheMethodOverTheController(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeController(t, root, "ExampleController.go", strings.Join([]string{
		`// @RequestRoute("/api/v1/example")`,
		`// @Allow(Administrator)`,
		`type ExampleController struct{}`,
		``,
		`// @PostRoute("/inherited")`,
		`func (controller *ExampleController) PostInherited() {}`,
		``,
		`// @PostRoute("/opened")`,
		`// @Public`,
		`func (controller *ExampleController) PostOpened() {}`,
		``,
		`// @PostRoute("/conflicting")`,
		`// @Public`,
		`// @SignedIn`,
		`func (controller *ExampleController) PostConflicting() {}`,
		``,
		`// @PostRoute("/auditor")`,
		`// @Allow(Auditor)`,
		`func (controller *ExampleController) PostAuditor() {}`,
	}, "\n"))
	writeController(t, root, "BareController.go", strings.Join([]string{
		`// @RequestRoute("/api/v1/bare")`,
		`type BareController struct{}`,
		``,
		`// @PostRoute("/unguarded")`,
		`func (controller *BareController) PostUnguarded() {}`,
	}, "\n"))

	declared := loadDeclaredAccess(t, root)
	wanted := map[string]string{
		"POST /api/v1/example/inherited":   "[administrator]",
		"POST /api/v1/example/opened":      "[public]",
		"POST /api/v1/example/conflicting": "[public signed_in]",
		"POST /api/v1/example/auditor":     "[allow(Auditor)]",
		"POST /api/v1/bare/unguarded":      "[]",
	}
	for route, want := range wanted {
		if got := fmt.Sprint(declared[route]); got != want {
			t.Errorf("%s declares %s; want %s", route, got, want)
		}
	}
}

func TestRouteAccessProblemsNameEveryDisagreement(t *testing.T) {
	t.Parallel()

	declared := declaredAccessTable{
		"POST /api/v1/example/matching":    {accessAdministrator},
		"POST /api/v1/example/weakened":    {accessAdministrator},
		"POST /api/v1/example/unrecorded":  {accessSignedIn},
		"POST /api/v1/example/unguarded":   nil,
		"POST /api/v1/example/conflicting": {accessPublic, accessSignedIn},
		"POST /api/v1/example/unlisted":    {accessPublic},
	}
	coverages := map[string]operationCoverage{
		"example.operation": {
			Category: coverageRouted,
			Routes: []string{
				"POST /api/v1/example/matching",
				"POST /api/v1/example/weakened",
				"POST /api/v1/example/unrecorded",
				"POST /api/v1/example/unguarded",
				"POST /api/v1/example/conflicting",
			},
			Access: map[string]string{
				"POST /api/v1/example/matching":    accessAdministrator,
				"POST /api/v1/example/weakened":    accessSignedIn,
				"POST /api/v1/example/unguarded":   accessPublic,
				"POST /api/v1/example/conflicting": "everyone",
				"POST /api/v1/example/stray":       accessPublic,
			},
		},
	}
	want := []string{
		"POST /api/v1/example/conflicting declares 2 access annotations [public signed_in]; want exactly one",
		"POST /api/v1/example/unguarded declares 0 access annotations []; want exactly one",
		"POST /api/v1/example/unlisted has no recorded access in http_coverage",
		"POST /api/v1/example/unrecorded has no recorded access in http_coverage",
		`example.operation lists POST /api/v1/example/unrecorded without recording its access`,
		`example.operation records POST /api/v1/example/conflicting as "everyone"; want one of: ` + accessNamesDescribed,
		"example.operation records POST /api/v1/example/weakened as signed_in, but its controller declares administrator",
		"example.operation records access for POST /api/v1/example/stray, which it does not list",
	}
	sort.Strings(want)
	got := routeAccessProblems(coverages, declared)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func writeController(t *testing.T, root string, name string, content string) {
	t.Helper()

	directory := filepath.Join(root, filepath.FromSlash(serverDirectory), controllersDirectory)
	if err := os.MkdirAll(directory, controllerDirectories); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), []byte(content+"\n"), controllerFileMode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
