package contract_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMachineSchemaAndFixturesAreValidJSON(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	schema, err := os.ReadFile(filepath.Join(root, "api", "schema", "machine-v1.schema.json"))
	if err != nil {
		t.Fatalf("ReadFile(schema) error = %v", err)
	}
	if !json.Valid(schema) {
		t.Fatal("machine-v1.schema.json is not valid JSON")
	}

	fixtures, err := os.Open(filepath.Join(root, "api", "machine", "v1", "fixtures.ndjson"))
	if err != nil {
		t.Fatalf("Open(fixtures) error = %v", err)
	}
	defer fixtures.Close()

	scanner := bufio.NewScanner(fixtures)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if !json.Valid(scanner.Bytes()) {
			t.Fatalf("fixtures.ndjson line %d is not valid JSON", lineNumber)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan fixtures: %v", err)
	}
	if lineNumber == 0 {
		t.Fatal("fixtures.ndjson is empty")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
