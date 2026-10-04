package remotes

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
)

type Generator struct {
	root string
}

func NewGenerator(root string) Generator {
	return Generator{root: root}
}

func (generator Generator) Files() (map[string][]byte, error) {
	manifest, manifestFailure := generator.manifest()
	families, familyFailure := FamilyIndex{}.Families(RouteReader{manifest: manifest}.Routes())
	sets, setFailure := generator.templateSets()
	return generator.rendered(sets, families, errors.Join(manifestFailure, familyFailure, setFailure))
}

func (generator Generator) Write(output string) error {
	files, failure := generator.Files()
	sets, setFailure := generator.templateSets()
	return generator.replaced(output, sets, files, errors.Join(failure, setFailure))
}

func (generator Generator) manifest() (Manifest, error) {
	var manifest Manifest
	content, failure := os.ReadFile(filepath.Join(generator.root, "api", "machine", "v1", "operations.json"))
	return manifest, errors.Join(failure, json.Unmarshal(content, &manifest))
}

func (generator Generator) templateSets() ([]TemplateSet, error) {
	folder := filepath.Join(generator.root, "tools", "remotes", "templates")
	entries, failure := os.ReadDir(folder)
	sets := []TemplateSet{}
	for _, entry := range entries {
		sets = append(sets, TemplateSet{Language: entry.Name(), folder: filepath.Join(folder, entry.Name())})
	}
	return sets, failure
}

func (generator Generator) rendered(sets []TemplateSet, families []RemoteFamily, failure error) (map[string][]byte, error) {
	if failure != nil {
		return nil, failure
	}
	files := map[string][]byte{}
	failures := []error{}
	for _, set := range sets {
		rendered, renderFailure := set.Render(families)
		maps.Copy(files, rendered)
		failures = append(failures, renderFailure)
	}
	return files, errors.Join(failures...)
}

func (generator Generator) replaced(output string, sets []TemplateSet, files map[string][]byte, failure error) error {
	if failure != nil {
		return failure
	}
	failures := []error{}
	for _, set := range sets {
		failures = append(failures, os.RemoveAll(filepath.Join(output, set.Language)))
	}
	return errors.Join(append(failures, generator.written(output, files))...)
}

func (generator Generator) written(output string, files map[string][]byte) error {
	failures := []error{}
	for name, content := range files {
		target := filepath.Join(output, filepath.FromSlash(name))
		failures = append(failures, os.MkdirAll(filepath.Dir(target), generator.folderMode()))
		failures = append(failures, os.WriteFile(target, content, generator.fileMode()))
	}
	return errors.Join(failures...)
}

func (generator Generator) folderMode() os.FileMode {
	return 0o755
}

func (generator Generator) fileMode() os.FileMode {
	return 0o644
}
