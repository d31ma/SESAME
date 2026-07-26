// Command crap reports the Change Risk Anti-Patterns score for every function
// in the module, and fails when any exceeds a threshold.
//
//	CRAP(m) = comp(m)^2 * (1 - cov(m))^3 + comp(m)
//
// where comp is cyclomatic complexity and cov is statement coverage as a
// fraction. The metric's point is that complexity is only tolerable when it is
// covered: an uncovered branch-heavy function scores catastrophically, and the
// two ways down are to simplify it or to test it.
//
// Worth knowing before choosing a threshold, because the shape surprises
// people: the additive `+ comp(m)` term means CRAP can never fall below the
// complexity itself. A function of complexity 6 scores at least 6 no matter
// how perfectly it is tested. So a maximum of 5 is not "keep things tidy" —
// it is a hard cap of five branches per function, and complexity 5 demands
// exactly 100% coverage. The original paper suggests 30.
//
// Usage:
//
//	go test -coverpkg=./... -coverprofile=cover.out ./...
//	go run ./tools/crap -profile cover.out -max 30
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type function struct {
	File       string
	Line       int
	Name       string
	Complexity int
	Coverage   float64
	Score      float64
}

func main() {
	profile := flag.String("profile", "", "coverage profile from `go test -coverprofile`")
	max := flag.Float64("max", 30, "fail if any function scores above this")
	top := flag.Int("top", 25, "how many of the worst offenders to print")
	root := flag.String("root", ".", "module root to scan")
	flag.Parse()

	if *profile == "" {
		fatal("a coverage profile is required: -profile cover.out")
	}
	moduleRoot, err := filepath.Abs(*root)
	if err != nil {
		fatal("resolve root: %v", err)
	}

	complexities, err := scanComplexity(moduleRoot)
	if err != nil {
		fatal("scan complexity: %v", err)
	}
	module, err := modulePath(moduleRoot)
	if err != nil {
		fatal("read module path: %v", err)
	}
	coverage, err := readCoverage(*profile, module)
	if err != nil {
		fatal("read coverage: %v", err)
	}
	// If nothing joined, every score would be inflated by a bad key rather
	// than by real risk, and the report would be confidently wrong.
	joined := 0
	for identifier := range complexities {
		if _, ok := coverage[identifier]; ok {
			joined++
		}
	}
	if joined == 0 {
		fatal("no function in the profile matched the scanned source; the profile is stale or from another module")
	}

	functions := make([]function, 0, len(complexities))
	for key, entry := range complexities {
		// A function absent from the profile was never compiled into a
		// covered package. Treating that as zero coverage is the honest
		// reading: nothing exercised it.
		entry.Coverage = coverage[key]
		entry.Score = crap(entry.Complexity, entry.Coverage)
		functions = append(functions, entry)
	}
	sort.Slice(functions, func(i, j int) bool {
		if functions[i].Score != functions[j].Score {
			return functions[i].Score > functions[j].Score
		}
		return functions[i].File+functions[i].Name < functions[j].File+functions[j].Name
	})

	over := 0
	for _, entry := range functions {
		if entry.Score > *max {
			over++
		}
	}

	fmt.Printf("%d functions scanned, %d over CRAP %.0f\n\n", len(functions), over, *max)
	shown := *top
	if over > 0 && over < shown {
		shown = over
	}
	if shown > len(functions) {
		shown = len(functions)
	}
	fmt.Printf("%-9s %5s %8s  %s\n", "CRAP", "cplx", "cov", "function")
	for _, entry := range functions[:shown] {
		fmt.Printf("%-9.1f %5d %7.1f%%  %s:%d %s\n",
			entry.Score, entry.Complexity, entry.Coverage*100,
			entry.File, entry.Line, entry.Name)
	}

	if over > 0 {
		fmt.Fprintf(os.Stderr, "\n%d function(s) exceed CRAP %.0f\n", over, *max)
		os.Exit(1)
	}
	fmt.Printf("\nall functions are at or below CRAP %.0f\n", *max)
}

// crap is the metric itself.
func crap(complexity int, coverage float64) float64 {
	uncovered := 1 - coverage
	return math.Pow(float64(complexity), 2)*math.Pow(uncovered, 3) + float64(complexity)
}

// key identifies a function across both inputs. File and declaration line are
// used rather than the name, because `go tool cover` prints an unqualified
// method name and two types in one file may share one.
type key struct {
	File string
	Line int
}

// scanComplexity walks the module and measures every function.
func scanComplexity(root string) (map[key]function, error) {
	found := map[key]function{}
	fileSet := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "graphify-out", "testdata", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Test files are the measuring instrument, not the thing measured.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(fileSet, path, nil, 0)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}
		for _, declaration := range parsed.Decls {
			declared, ok := declaration.(*ast.FuncDecl)
			if !ok || declared.Body == nil {
				continue
			}
			position := fileSet.Position(declared.Pos())
			relativePath, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			relativePath = filepath.ToSlash(relativePath)
			found[key{File: relativePath, Line: position.Line}] = function{
				File:       relativePath,
				Line:       position.Line,
				Name:       functionName(declared),
				Complexity: complexity(declared),
			}
		}
		return nil
	})
	return found, err
}

func functionName(declared *ast.FuncDecl) string {
	if declared.Recv == nil || len(declared.Recv.List) == 0 {
		return declared.Name.Name
	}
	var receiver string
	switch expression := declared.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if identifier, ok := expression.X.(*ast.Ident); ok {
			receiver = "*" + identifier.Name
		}
	case *ast.Ident:
		receiver = expression.Name
	}
	return "(" + receiver + ")." + declared.Name.Name
}

// complexity counts decision points the way gocyclo does: one for the
// function, plus one for each branch, loop, case, and short-circuit operator.
func complexity(declared *ast.FuncDecl) int {
	count := 1
	ast.Inspect(declared, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
			count++
		case *ast.BinaryExpr:
			if typed.Op == token.LAND || typed.Op == token.LOR {
				count++
			}
		}
		return true
	})
	return count
}

// readCoverage runs `go tool cover -func` and reads the per-function
// percentages back out, keyed by path relative to the module root.
//
// The profile names files by import path and the scan names them by
// filesystem path, so the module prefix is stripped to bring the two onto the
// same footing. Getting this join wrong is silent — every function would look
// uncovered and every score would be inflated — so a total mismatch is
// reported as an error rather than as an alarming report.
func readCoverage(profile, modulePath string) (map[key]float64, error) {
	command := exec.Command("go", "tool", "cover", "-func="+profile)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go tool cover: %w", err)
	}

	coverage := map[key]float64{}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[0] == "total:" {
			continue
		}
		location := strings.Split(fields[0], ":")
		if len(location) < 3 {
			continue
		}
		line, convErr := strconv.Atoi(location[len(location)-2])
		if convErr != nil {
			continue
		}
		percent, convErr := strconv.ParseFloat(
			strings.TrimSuffix(fields[len(fields)-1], "%"), 64)
		if convErr != nil {
			continue
		}
		path := strings.Join(location[:len(location)-2], ":")
		path = strings.TrimPrefix(strings.TrimPrefix(path, modulePath), "/")
		coverage[key{File: path, Line: line}] = percent / 100
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(coverage) == 0 {
		return nil, errors.New("the coverage profile named no functions")
	}
	return coverage, nil
}

// modulePath reads the module path from go.mod, so the import-path prefix can
// be stripped from coverage entries.
func modulePath(root string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if after, found := strings.CutPrefix(strings.TrimSpace(line), "module "); found {
			return strings.TrimSpace(after), nil
		}
	}
	return "", errors.New("go.mod declares no module path")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
