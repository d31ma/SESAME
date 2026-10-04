package contract_test

import (
	"go/ast"
	"go/token"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var methodRouteAnnotation = regexp.MustCompile(`^// @(Get|Post|Put|Patch|Delete)Route\("([^"]*)"\)`)

type routeTable map[string]map[string]struct{}

func loadRouteTable(t *testing.T, root string) routeTable {
	t.Helper()

	source := parseControllers(t, filepath.Join(root, filepath.FromSlash(serverDirectory), controllersDirectory))
	table := routeTable{}
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
			table[route] = namedStrings(method, methods)
		}
	}
	if len(table) == 0 {
		t.Fatal("no Yon routes were found in app/server/controllers")
	}
	return table
}

func routeOf(prefix string, method *ast.FuncDecl) (string, bool) {
	match, found := annotation(method.Doc, methodRouteAnnotation)
	if !found {
		return "", false
	}
	return strings.ToUpper(match[1]) + " " + path.Join(prefix, match[2]), true
}

func namedStrings(method *ast.FuncDecl, siblings map[string]*ast.FuncDecl) map[string]struct{} {
	named := map[string]struct{}{}
	visited := map[string]bool{}
	var visit func(declaration *ast.FuncDecl)
	visit = func(declaration *ast.FuncDecl) {
		if visited[declaration.Name.Name] {
			return
		}
		visited[declaration.Name.Name] = true
		ast.Inspect(declaration.Body, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.BasicLit:
				if value, err := strconv.Unquote(typed.Value); err == nil && typed.Kind == token.STRING {
					named[value] = struct{}{}
				}
			case *ast.SelectorExpr:
				if sibling, isSibling := siblings[typed.Sel.Name]; isSibling && isReceiver(typed.X, declaration) {
					visit(sibling)
				}
			}
			return true
		})
	}
	visit(method)
	return named
}

func isReceiver(expression ast.Expr, declaration *ast.FuncDecl) bool {
	name, isName := expression.(*ast.Ident)
	receiverNames := declaration.Recv.List[0].Names
	return isName && len(receiverNames) > 0 && name.Name == receiverNames[0].Name
}
