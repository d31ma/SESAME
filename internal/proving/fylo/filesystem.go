package fylo

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func osMkdirPrivateTemp(pattern string) (string, error) {
	root, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("create private temporary directory: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return "", fmt.Errorf("restrict private temporary directory: %w", err)
	}
	return root, nil
}

func removePrivateTree(root string) error {
	temporaryRoot := filepath.Clean(os.TempDir()) + string(os.PathSeparator)
	cleaned := filepath.Clean(root)
	if !strings.HasPrefix(cleaned+string(os.PathSeparator), temporaryRoot) {
		return fmt.Errorf("refuse to remove non-temporary path %q", root)
	}
	if err := os.RemoveAll(cleaned); err != nil {
		return fmt.Errorf("remove temporary tree %q: %w", cleaned, err)
	}
	return nil
}

func RemoveDerivedIndex(root, collection string) error {
	target := filepath.Join(root, ".collections", collection, "index")
	expectedPrefix := filepath.Join(filepath.Clean(root), ".collections") + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), expectedPrefix) {
		return fmt.Errorf("refuse to remove index outside FYLO root: %s", target)
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("remove derived index for %s: %w", collection, err)
	}
	return nil
}

func CopyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case entry.Type()&os.ModeSymlink != 0:
			return fmt.Errorf("refuse to copy symlink %s", path)
		case entry.IsDir():
			if relative == "." {
				return nil
			}
			return os.MkdirAll(target, info.Mode().Perm())
		case entry.Type().IsRegular():
			return copyRegularFile(path, target, info.Mode().Perm())
		default:
			return fmt.Errorf("unsupported backup entry %s", path)
		}
	})
}

func copyRegularFile(source, destination string, mode fs.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()

	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	return errors.Join(copyErr, closeErr)
}

// corruptDocument overwrites one stored document with unparseable bytes, so
// recovery can be proven against a root that really is damaged.
//
// The shard directory is found rather than assumed. The Bun runtime used the
// first two identifier characters. Rust releases use a collection-specific
// width of one to four trailing characters, with two as the v26.31.06 default
// and one from v26.32.07 onward. More than one layout can therefore exist in
// roots that cross a release or contain differently configured collections.
func corruptDocument(root, collection, id string) error {
	if len(id) < 2 {
		return errors.New("FYLO document ID is too short")
	}
	documents := filepath.Join(root, ".collections", collection, "docs")
	target, err := findDocumentFile(documents, id)
	if err != nil {
		return err
	}
	expectedPrefix := filepath.Join(filepath.Clean(root), ".collections") + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(target), expectedPrefix) {
		return fmt.Errorf("refuse to corrupt document outside FYLO root: %s", target)
	}
	if err := os.WriteFile(target, []byte("{corrupt"), 0o600); err != nil {
		return fmt.Errorf("corrupt copied event document: %w", err)
	}
	return nil
}

// findDocumentFile locates a stored document under whichever shard FYLO chose.
func findDocumentFile(documents, id string) (string, error) {
	name := id + ".json"
	// Try every released layout before falling back to a contained walk. The
	// walk remains important because this proving harness must detect a future
	// layout change by finding and corrupting the actual authoritative record.
	shards := []string{id[:2]}
	for width := 1; width <= 4 && width <= len(id); width++ {
		shards = append(shards, id[len(id)-width:])
	}
	for _, shard := range shards {
		candidate := filepath.Join(documents, shard, name)
		regular, err := regularDocumentCandidate(candidate)
		if err != nil {
			return "", err
		}
		if regular {
			return candidate, nil
		}
	}
	return findDocumentByWalk(documents, name, id)
}

func regularDocumentCandidate(candidate string) (bool, error) {
	info, err := os.Lstat(candidate)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect document candidate %s: %w", candidate, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refuse document symlink %s", candidate)
	}
	return info.Mode().IsRegular(), nil
}

func findDocumentByWalk(documents, name, id string) (string, error) {
	// A scheme neither of those covers is a change worth failing loudly on,
	// but not one worth failing the whole run over if the document is there.
	var found string
	walkErr := filepath.WalkDir(documents, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() != name {
			return nil
		}
		regular, err := regularDocumentCandidate(path)
		if err != nil {
			return err
		}
		if !regular {
			return nil
		}
		found = path
		return fs.SkipAll
	})
	if walkErr != nil {
		return "", fmt.Errorf("search %s for document %s: %w", documents, id, walkErr)
	}
	if found == "" {
		return "", fmt.Errorf("document %s is not stored anywhere under %s", id, documents)
	}
	return found, nil
}
