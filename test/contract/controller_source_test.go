package contract_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

const yonHandlerPackageClause = "package main\n"

var controllerPrefixAnnotation = regexp.MustCompile(`^// @RequestRoute\("([^"]*)"\)`)

type controllerSource struct {
	prefixes map[string]string
	methods  map[string]map[string]*ast.FuncDecl
}

func parseControllers(t *testing.T, directory string) controllerSource {
	t.Helper()

	names, err := filepath.Glob(filepath.Join(directory, "*.go"))
	if err != nil || len(names) == 0 {
		t.Fatalf("list the Yon controllers in %s: %v", directory, err)
	}
	source := controllerSource{prefixes: map[string]string{}, methods: map[string]map[string]*ast.FuncDecl{}}
	for _, name := range names {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, yonHandlerPackageClause+string(content), parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		source.add(file)
	}
	return source
}

func (source controllerSource) add(file *ast.File) {
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			source.addPrefix(typed)
		case *ast.FuncDecl:
			source.addMethod(typed)
		}
	}
}

func (source controllerSource) addPrefix(declaration *ast.GenDecl) {
	for _, specification := range declaration.Specs {
		typeSpecification, isType := specification.(*ast.TypeSpec)
		if !isType {
			continue
		}
		if prefix, found := annotation(declaration.Doc, controllerPrefixAnnotation); found {
			source.prefixes[typeSpecification.Name.Name] = prefix[1]
		}
	}
}

func (source controllerSource) addMethod(declaration *ast.FuncDecl) {
	receiver := receiverTypeName(declaration)
	if receiver == "" {
		return
	}
	if source.methods[receiver] == nil {
		source.methods[receiver] = map[string]*ast.FuncDecl{}
	}
	source.methods[receiver][declaration.Name.Name] = declaration
}

func receiverTypeName(declaration *ast.FuncDecl) string {
	if declaration.Recv == nil || len(declaration.Recv.List) == 0 {
		return ""
	}
	receiverType := declaration.Recv.List[0].Type
	if pointer, isPointer := receiverType.(*ast.StarExpr); isPointer {
		receiverType = pointer.X
	}
	if name, isName := receiverType.(*ast.Ident); isName {
		return name.Name
	}
	return ""
}

func annotation(comments *ast.CommentGroup, pattern *regexp.Regexp) ([]string, bool) {
	if comments == nil {
		return nil, false
	}
	for _, comment := range comments.List {
		if match := pattern.FindStringSubmatch(comment.Text); match != nil {
			return match, true
		}
	}
	return nil, false
}
