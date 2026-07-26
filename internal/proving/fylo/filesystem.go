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

func corruptDocument(root, collection, id string) error {
	if len(id) < 2 {
		return errors.New("FYLO document ID is too short")
	}
	target := filepath.Join(
		root,
		".collections",
		collection,
		"docs",
		id[:2],
		id+".json",
	)
	expectedPrefix := filepath.Join(filepath.Clean(root), ".collections") + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(target), expectedPrefix) {
		return fmt.Errorf("refuse to corrupt document outside FYLO root: %s", target)
	}
	if err := os.WriteFile(target, []byte("{corrupt"), 0o600); err != nil {
		return fmt.Errorf("corrupt copied event document: %w", err)
	}
	return nil
}
