package fylo

import (
	"os"
	"path/filepath"
	"runtime"
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
