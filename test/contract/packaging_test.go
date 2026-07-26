package contract_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SESAME distributes its clients the way FYLO does: one file per language,
// shipped as sesame-clients.tar.gz and copied into the consuming project.
// There are no package manifests, so nothing but these tests describes what a
// release is obliged to contain.
const versionFile = "VERSION"

// distributedShim is the one file a developer copies for a given language.
type distributedShim struct {
	directory string
	file      string
}

var distributedShims = []distributedShim{
	{"node", "sesame.mjs"},
	{"python", "sesame.py"},
	{"rust", "sesame.rs"},
	{"java", "Sesame.java"},
	{"kotlin", "Sesame.kt"},
	{"csharp", "Sesame.cs"},
	{"php", "sesame.php"},
	{"ruby", "sesame.rb"},
	{"dart", "sesame.dart"},
}

// TestEveryShimIsPresent fails if a client the release claims to ship is
// missing or has been renamed. With no manifest to declare contents, a rename
// would otherwise reach a user as a tarball that silently lacks their
// language.
func TestEveryShimIsPresent(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	for _, shim := range distributedShims {
		t.Run(shim.directory, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(root, "clients", shim.directory, shim.file)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("clients/%s/%s is missing: %v", shim.directory, shim.file, err)
			}
			if info.Size() == 0 {
				t.Fatalf("clients/%s/%s is empty", shim.directory, shim.file)
			}
		})
	}
}

// TestEveryClientIsAccountedFor stops a new SDK from arriving with no
// distribution story. Go is the one deliberate exception: it lives inside the
// engine's own module, so `go get` resolves it at the tag and copying a file
// would be a downgrade.
func TestEveryClientIsAccountedFor(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "clients"))
	if err != nil {
		t.Fatalf("read clients: %v", err)
	}

	distributed := map[string]bool{"go": true}
	for _, shim := range distributedShims {
		distributed[shim.directory] = true
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !distributed[entry.Name()] {
			t.Errorf("clients/%s has no entry in distributedShims and is not "+
				"the Go module exception", entry.Name())
		}
	}
}

// TestClientBundleCarriesTheLicence covers Apache-2.0 section 4: the tarball
// travels without the repository, so the licence has to be inside it.
func TestClientBundleCarriesTheLicence(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	canonical, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		t.Fatalf("read the repository licence: %v", err)
	}
	carried, err := os.ReadFile(filepath.Join(root, "clients", "LICENSE"))
	if err != nil {
		t.Fatalf("read the bundled licence: %v", err)
	}
	if string(carried) != string(canonical) {
		t.Fatal("clients/LICENSE differs from the repository licence")
	}
}

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
