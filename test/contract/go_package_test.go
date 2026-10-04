package contract_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	goPackageLanguage  = "Go"
	goPackageDirectory = "app/server/packages"
)

var retiredClientMarkers = []string{"clients/", "sesame-clients.tar.gz"}

func goPackageSource(t *testing.T, root string) string {
	t.Helper()

	names, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(goPackageDirectory), "sesame", "*.go"))
	if err != nil || len(names) == 0 {
		t.Fatalf("list the Go package sources: %v", err)
	}
	var builder strings.Builder
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		builder.Write(content)
	}
	return builder.String()
}

func goSDKClientFile(root string) string {
	return filepath.Join(root, filepath.FromSlash(goPackageDirectory), "sesame", "client.go")
}
