package machine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

const publishedRoot = "../../.."

type publishedSchema struct {
	Defs struct {
		Request struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"request"`
		Actor struct {
			Required   []string                   `json:"required"`
			Properties map[string]json.RawMessage `json:"properties"`
			MaxLength  int                        `json:"x-max-serialized-bytes"`
		} `json:"actor"`
		Error struct {
			Properties struct {
				Code struct {
					Enum []string `json:"enum"`
				} `json:"code"`
			} `json:"properties"`
		} `json:"error"`
		VersionResult struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"system_version_result"`
	} `json:"$defs"`
}

func loadPublishedSchema(t *testing.T) publishedSchema {
	t.Helper()

	encoded, err := os.ReadFile(filepath.Join(publishedRoot, "api", "schema", "machine-v1.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema publishedSchema
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	return schema
}

func TestPublishedFixturesReplayByteForByte(t *testing.T) {
	t.Parallel()

	fixtures, err := os.Open(filepath.Join(publishedRoot, "api", "machine", "v1", "fixtures.ndjson"))
	if err != nil {
		t.Fatalf("open fixtures: %v", err)
	}
	defer fixtures.Close()

	var lines []string
	scanner := bufio.NewScanner(fixtures)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines)%2 != 0 {
		t.Fatalf("fixtures hold %d lines; want request/response pairs", len(lines))
	}
	for index := 0; index < len(lines); index += 2 {
		request, want := lines[index], lines[index+1]
		if strings.Contains(request, `"system.metrics"`) {
			continue
		}
		var output bytes.Buffer
		processor := fixtureProcessor(t, want)
		if err := processor.Run(context.Background(), strings.NewReader(request+"\n"), &output); err != nil {
			t.Fatalf("Run(%s) error = %v", request, err)
		}
		if got := strings.TrimSpace(output.String()); got != want {
			t.Errorf("fixture %d\nrequest: %s\ngot:  %s\nwant: %s", index/2+1, request, got, want)
		}
	}
}

func fixtureProcessor(t *testing.T, response string) *Processor {
	t.Helper()

	information := system.New(buildinfo.New("", "", ""))
	if strings.Contains(response, `"code":"`+ErrorStorageNotConfigured+`"`) {
		return New(information, nil)
	}
	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	return New(information, service)
}

func TestSchemaListsEveryErrorCode(t *testing.T) {
	t.Parallel()

	published := loadPublishedSchema(t).Defs.Error.Properties.Code.Enum
	sort.Strings(published)
	defined := definedErrorCodes(t)
	if strings.Join(published, ",") != strings.Join(defined, ",") {
		t.Fatalf("schema error codes drifted from the engine\nschema: %v\nengine: %v", published, defined)
	}
}

func definedErrorCodes(t *testing.T) []string {
	t.Helper()

	files := token.NewFileSet()
	packages, err := parser.ParseDir(files, ".", func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	var codes []string
	for _, file := range packages["machine"].Files {
		ast.Inspect(file, func(node ast.Node) bool {
			codes = append(codes, errorCodeValues(node)...)
			return true
		})
	}
	sort.Strings(codes)
	return codes
}

func errorCodeValues(node ast.Node) []string {
	spec, isValue := node.(*ast.ValueSpec)
	if !isValue {
		return nil
	}
	var codes []string
	for index, name := range spec.Names {
		if !strings.HasPrefix(name.Name, "Error") || index >= len(spec.Values) {
			continue
		}
		literal, isLiteral := spec.Values[index].(*ast.BasicLit)
		if !isLiteral || literal.Kind != token.STRING {
			continue
		}
		value, _ := strconv.Unquote(literal.Value)
		codes = append(codes, value)
	}
	return codes
}

func TestSchemaDescribesEveryRequestField(t *testing.T) {
	t.Parallel()

	properties := loadPublishedSchema(t).Defs.Request.Properties
	fields := reflect.TypeOf(Request{})
	for index := 0; index < fields.NumField(); index++ {
		field := fields.Field(index)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if _, documented := properties[name]; !documented {
			t.Fatalf("request field %q is missing from the schema", name)
		}
	}
	if len(properties) != countExportedFields(fields) {
		t.Fatalf("schema request properties %d, engine request fields %d", len(properties), countExportedFields(fields))
	}
}

func countExportedFields(fields reflect.Type) int {
	count := 0
	for index := 0; index < fields.NumField(); index++ {
		if fields.Field(index).IsExported() {
			count++
		}
	}
	return count
}

func TestSchemaDescribesTheActorTheEngineAccepts(t *testing.T) {
	t.Parallel()

	actor := loadPublishedSchema(t).Defs.Actor
	required := append([]string(nil), actor.Required...)
	sort.Strings(required)
	if strings.Join(required, ",") != "principal_id,session_id,tenant_id" || len(actor.Properties) != len(required) {
		t.Fatalf("schema actor = %#v", actor)
	}
	if actor.MaxLength != MaxActorBytes {
		t.Fatalf("schema actor size bound = %d, engine = %d", actor.MaxLength, MaxActorBytes)
	}
}

func TestSchemaDescribesTheVersionAdvertisement(t *testing.T) {
	t.Parallel()

	properties := loadPublishedSchema(t).Defs.VersionResult.Properties
	fields := reflect.TypeOf(VersionReport{})
	if len(properties) != fields.NumField() {
		t.Fatalf("schema system.version properties %d, engine fields %d", len(properties), fields.NumField())
	}
	for index := 0; index < fields.NumField(); index++ {
		name := strings.Split(fields.Field(index).Tag.Get("json"), ",")[0]
		if _, documented := properties[name]; !documented {
			t.Fatalf("system.version field %q is missing from the schema", name)
		}
	}
}
