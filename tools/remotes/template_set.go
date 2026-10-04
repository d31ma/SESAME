package remotes

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"
)

type TemplateSet struct {
	Language string
	folder   string
	families []RemoteFamily
	files    map[string][]byte
}

func (set TemplateSet) Render(families []RemoteFamily) (map[string][]byte, error) {
	set.families = families
	set.files = map[string][]byte{}
	names, walkFailure := set.templateNames()
	return set.files, errors.Join(walkFailure, set.renderAll(names))
}

func (set TemplateSet) templateNames() ([]string, error) {
	names := []string{}
	failure := filepath.WalkDir(set.folder, func(name string, entry fs.DirEntry, walkFailure error) error {
		names = set.withFile(names, name, entry, walkFailure)
		return walkFailure
	})
	return names, failure
}

func (set TemplateSet) withFile(names []string, name string, entry fs.DirEntry, walkFailure error) []string {
	if walkFailure != nil || entry.IsDir() {
		return names
	}
	return append(names, name)
}

func (set TemplateSet) renderAll(names []string) error {
	failures := []error{}
	for _, name := range names {
		failures = append(failures, set.renderFile(name))
	}
	return errors.Join(failures...)
}

func (set TemplateSet) renderFile(name string) error {
	relative, relativeFailure := filepath.Rel(set.folder, name)
	parsed, parseFailure := set.parsed(name)
	output := set.Language + "/" + strings.TrimSuffix(filepath.ToSlash(relative), set.templateSuffix())
	return set.renderOutput(output, parsed, errors.Join(relativeFailure, parseFailure, set.checkedSuffix(name)))
}

func (set TemplateSet) parsed(name string) (*template.Template, error) {
	content, readFailure := os.ReadFile(name)
	parsed, parseFailure := template.New(filepath.Base(name)).Option(set.strictKeys()).Parse(string(content))
	return parsed, errors.Join(readFailure, parseFailure)
}

func (set TemplateSet) checkedSuffix(name string) error {
	if strings.HasSuffix(name, set.templateSuffix()) {
		return nil
	}
	return fmt.Errorf("%s: every file in a template set ends in %s", name, set.templateSuffix())
}

func (set TemplateSet) renderOutput(output string, parsed *template.Template, failure error) error {
	directory, base := path.Split(output)
	extension, perFamily := strings.CutPrefix(base, set.familyStem())
	switch {
	case failure != nil:
		return failure
	case perFamily:
		return set.renderFamilies(parsed, directory, extension)
	}
	return set.renderOnce(parsed, output)
}

func (set TemplateSet) renderOnce(parsed *template.Template, output string) error {
	rendered, failure := set.rendered(parsed, TemplateView{Families: set.families})
	set.files[output] = rendered
	return failure
}

func (set TemplateSet) renderFamilies(parsed *template.Template, directory string, extension string) error {
	failures := []error{}
	for _, family := range set.families {
		rendered, failure := set.rendered(parsed, TemplateView{Families: set.families, Family: family})
		set.files[directory+family.ClassName()+extension] = rendered
		failures = append(failures, failure)
	}
	return errors.Join(failures...)
}

func (set TemplateSet) rendered(parsed *template.Template, view TemplateView) ([]byte, error) {
	var rendered bytes.Buffer
	failure := parsed.Execute(&rendered, view)
	return rendered.Bytes(), failure
}

func (set TemplateSet) templateSuffix() string {
	return ".tmpl"
}

func (set TemplateSet) strictKeys() string {
	return "missingkey=error"
}

func (set TemplateSet) familyStem() string {
	return "Family"
}
