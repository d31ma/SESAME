package contract_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	servicesDirectory       = "services"
	publicCallServiceFile   = "PublicCallService.go"
	publicOperationsMethod  = "publicOperations"
	scimBearerGuard         = "ScimProvisioningService checks the SCIM bearer token"
	federatedLoginGuard     = "FederatedLoginService checks the operator's redirect allowlist"
	standardsDispatchGuard  = "StandardsDispatchService sends it through standards.dispatch"
	allowlistProblemsWanted = 2
)

func publicRouteGuards() map[string]string {
	return map[string]string{
		"federation.login_start": federatedLoginGuard,
		"saml.login_start":       federatedLoginGuard,
		"scim.group_create":      scimBearerGuard,
		"scim.group_deprovision": scimBearerGuard,
		"scim.group_get":         scimBearerGuard,
		"scim.group_list":        scimBearerGuard,
		"scim.group_patch":       scimBearerGuard,
		"scim.user_create":       scimBearerGuard,
		"scim.user_deprovision":  scimBearerGuard,
		"scim.user_get":          scimBearerGuard,
		"scim.user_list":         scimBearerGuard,
		"scim.user_patch":        scimBearerGuard,
		"oidc.authorize":         standardsDispatchGuard,
		"oidc.discovery":         standardsDispatchGuard,
		"oidc.introspect":        standardsDispatchGuard,
		"oidc.logout":            standardsDispatchGuard,
		"oidc.revoke":            standardsDispatchGuard,
		"oidc.token":             standardsDispatchGuard,
		"standards.dispatch":     standardsDispatchGuard,
	}
}

func loadPublicCallAllowlist(t *testing.T, root string) []string {
	t.Helper()

	name := filepath.Join(root, filepath.FromSlash(serverDirectory), servicesDirectory, publicCallServiceFile)
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), name, yonHandlerPackageClause+string(content), 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	allowlist := stringLiteralsIn(file, publicOperationsMethod)
	if len(allowlist) == 0 {
		t.Fatalf("%s has no %s method listing operations", publicCallServiceFile, publicOperationsMethod)
	}
	return allowlist
}

func stringLiteralsIn(file *ast.File, method string) []string {
	var literals []string
	for _, declaration := range file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Name.Name != method {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if literal, isLiteral := node.(*ast.BasicLit); isLiteral && literal.Kind == token.STRING {
				value, err := strconv.Unquote(literal.Value)
				if err == nil {
					literals = append(literals, value)
				}
			}
			return true
		})
	}
	return literals
}

func publicRouteOperations(coverages map[string]operationCoverage) []string {
	var operations []string
	for operation, coverage := range coverages {
		for _, access := range coverage.Access {
			if access == accessPublic {
				operations = append(operations, operation)
				break
			}
		}
	}
	return operations
}

func publicAllowlistProblems(allowlist []string, publicOperations []string, guards map[string]string) []string {
	var problems []string
	for _, operation := range allowlist {
		if !slices.Contains(publicOperations, operation) {
			problems = append(problems, fmt.Sprintf("%s is on the PublicCallService allowlist but no route records it as public in operations.json", operation))
		}
		if _, guarded := guards[operation]; guarded {
			problems = append(problems, fmt.Sprintf("%s is on the PublicCallService allowlist and also named as reached through another guard", operation))
		}
	}
	for _, operation := range publicOperations {
		_, guarded := guards[operation]
		if !guarded && !slices.Contains(allowlist, operation) {
			problems = append(problems, fmt.Sprintf("%s has a public route but is neither on the PublicCallService allowlist nor named with its other guard", operation))
		}
	}
	for operation := range guards {
		if !slices.Contains(publicOperations, operation) {
			problems = append(problems, fmt.Sprintf("%s is named as reached through another guard but has no public route in operations.json", operation))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestPublicCallAllowlistMatchesThePublicRoutes(t *testing.T) {
	t.Parallel()

	loaded, root := loadManifest(t)
	allowlist := loadPublicCallAllowlist(t, root)
	for _, problem := range publicAllowlistProblems(allowlist, publicRouteOperations(loaded.HTTPCoverage), publicRouteGuards()) {
		t.Error(problem)
	}
}

func TestPublicCallAllowlistReportsAnUnlistedPublicRouteAndAPrivilegedOperation(t *testing.T) {
	t.Parallel()

	problems := publicAllowlistProblems(
		[]string{"session.verify", "grant.create"},
		[]string{"session.verify", "system.ping"},
		map[string]string{},
	)

	if len(problems) != allowlistProblemsWanted {
		t.Fatalf("problems = %q, want one for grant.create and one for system.ping", problems)
	}
	if !slices.ContainsFunc(problems, func(problem string) bool { return problemNames(problem, "grant.create") }) {
		t.Errorf("problems = %q, want grant.create reported as not public", problems)
	}
	if !slices.ContainsFunc(problems, func(problem string) bool { return problemNames(problem, "system.ping") }) {
		t.Errorf("problems = %q, want system.ping reported as unlisted", problems)
	}
}

func problemNames(problem string, operation string) bool {
	return strings.HasPrefix(problem, operation+" ")
}
