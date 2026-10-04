package contract_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const versionFile = "VERSION"

// TestVersionIsASemanticVersion guards the file the release workflow checks
// against the tag it is building.
func TestVersionIsASemanticVersion(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), versionFile))
	if err != nil {
		t.Fatalf("read %s: %v", versionFile, err)
	}
	version := strings.TrimSpace(string(raw))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`).MatchString(version) {
		t.Fatalf("%s contains %q, which is not a semantic version", versionFile, version)
	}
}
