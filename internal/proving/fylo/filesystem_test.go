package fylo

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRemovePrivateTreeRefusesNonTemporaryPath(t *testing.T) {
	t.Parallel()

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := removePrivateTree(workingDirectory); err == nil {
		t.Fatal("removePrivateTree() accepted a non-temporary path")
	}
}

func TestRemoveDerivedIndexCannotEscapeRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	sentinel := filepath.Join(root, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := RemoveDerivedIndex(root, filepath.Join("..", "..")); err == nil {
		t.Fatal("RemoveDerivedIndex() accepted a traversal collection")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("sentinel was changed: %v", err)
	}
}

func TestCopyTreeCopiesRegularFilesAndRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ordinary Windows users cannot reliably create symlinks")
	}
	t.Parallel()

	source := t.TempDir()
	destination := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "document.json"), []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := CopyTree(source, destination); err != nil {
		t.Fatalf("CopyTree() error = %v", err)
	}
	copied, err := os.ReadFile(filepath.Join(destination, "document.json"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(copied) != `{"ok":true}` {
		t.Fatalf("copied content = %q", copied)
	}

	symlinkSource := t.TempDir()
	if err := os.Symlink(filepath.Join(source, "document.json"), filepath.Join(symlinkSource, "link")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := CopyTree(symlinkSource, t.TempDir()); err == nil {
		t.Fatal("CopyTree() accepted a symlink")
	}
}

func TestFindDocumentFileAcceptsEveryReleasedShardLayout(t *testing.T) {
	t.Parallel()

	const id = "4VWAU1MN77I"
	for _, shard := range []string{id[:2], id[len(id)-1:], id[len(id)-2:], id[len(id)-3:], id[len(id)-4:]} {
		shard := shard
		t.Run(shard, func(t *testing.T) {
			t.Parallel()

			documents := t.TempDir()
			directory := filepath.Join(documents, shard)
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatalf("Mkdir() error = %v", err)
			}
			want := filepath.Join(directory, id+".json")
			if err := os.WriteFile(want, []byte(`{"id":"`+id+`"}`), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			got, err := findDocumentFile(documents, id)
			if err != nil {
				t.Fatalf("findDocumentFile() error = %v", err)
			}
			if got != want {
				t.Fatalf("findDocumentFile() = %q, want %q", got, want)
			}
		})
	}
}

func TestFindDocumentFileUsesContainedFallbackForUnknownLayout(t *testing.T) {
	t.Parallel()

	const id = "4VWAU1MN77I"
	documents := t.TempDir()
	directory := filepath.Join(documents, "future-layout")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	want := filepath.Join(directory, id+".json")
	if err := os.WriteFile(want, []byte(`{"id":"`+id+`"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := findDocumentFile(documents, id)
	if err != nil {
		t.Fatalf("findDocumentFile() error = %v", err)
	}
	if got != want {
		t.Fatalf("findDocumentFile() = %q, want %q", got, want)
	}
}

func TestFindDocumentFileFailsWhenDocumentTreeOrDocumentIsMissing(t *testing.T) {
	t.Parallel()

	const id = "4VWAU1MN77I"
	for name, documents := range map[string]string{
		"missing tree":     filepath.Join(t.TempDir(), "missing"),
		"missing document": t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := findDocumentFile(documents, id); err == nil {
				t.Fatal("findDocumentFile() succeeded for missing input")
			}
		})
	}
}

func TestCorruptDocumentOverwritesOnlyAContainedRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ordinary Windows users cannot reliably create symlinks")
	}
	t.Parallel()

	const collection = "security-events"
	const id = "4VWAU1MN77I"
	root := t.TempDir()
	documents := filepath.Join(root, ".collections", collection, "docs", id[len(id)-1:])
	if err := os.MkdirAll(documents, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	target := filepath.Join(documents, id+".json")
	if err := os.WriteFile(target, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := corruptDocument(root, collection, id); err != nil {
		t.Fatalf("corruptDocument() error = %v", err)
	}
	corrupted, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(corrupted) != "{corrupt" {
		t.Fatalf("corrupted document = %q", corrupted)
	}

	outside := filepath.Join(t.TempDir(), id+".json")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write outside sentinel: %v", err)
	}
	symlinkRoot := t.TempDir()
	symlinkDirectory := filepath.Join(symlinkRoot, ".collections", collection, "docs", id[len(id)-1:])
	if err := os.MkdirAll(symlinkDirectory, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(symlinkDirectory, id+".json")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := corruptDocument(symlinkRoot, collection, id); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("corruptDocument() symlink error = %v", err)
	}
	contents, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read outside sentinel: %v", err)
	}
	if string(contents) != "keep" {
		t.Fatalf("outside sentinel changed to %q", contents)
	}
}

func TestCorruptDocumentRejectsShortIdentifierAndTraversal(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := corruptDocument(root, "security-events", "x"); err == nil {
		t.Fatal("corruptDocument() accepted a short identifier")
	}

	const id = "4VWAU1MN77I"
	outsideDocuments := filepath.Join(root, "outside", "docs", id[len(id)-1:])
	if err := os.MkdirAll(outsideDocuments, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	sentinel := filepath.Join(outsideDocuments, id+".json")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write traversal sentinel: %v", err)
	}
	collection := filepath.Join("..", "..", "outside")
	if err := corruptDocument(root, collection, id); err == nil {
		t.Fatal("corruptDocument() accepted a traversal collection")
	}
	contents, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("read traversal sentinel: %v", err)
	}
	if string(contents) != "keep" {
		t.Fatalf("traversal sentinel changed to %q", contents)
	}
}
