package contract_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDocsNeverExportADeploymentBesideAFYLOBinary guards a documentation
// mistake that costs a reader their first ten minutes.
//
// SESAME_DEPLOYMENT and FYLO_BINARY select two different modes — a deployment
// directory with verified snapshots, or a bare binary/root pair without them —
// and the engine refuses both at once rather than silently picking. The
// deployment records its own FYLO path in config.json, so there is no honest
// answer to which one wins.
//
// A quick-start that says `export SESAME_DEPLOYMENT` and `export FYLO_BINARY`
// therefore reads perfectly and breaks every command after `init`. It was
// written that way once, and it only surfaced because the sequence was run
// rather than reviewed. This is cheaper than running it.
func TestDocsNeverExportADeploymentBesideAFYLOBinary(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	// Snippets, not prose: the exclusivity rule is discussed in
	// docs/CONFIGURATION.md, and naming both variables in a sentence is how
	// that gets explained.
	fenced := regexp.MustCompile("(?s)```(?:bash|sh|console)?\\n(.*?)```")
	preformatted := regexp.MustCompile(`(?s)<pre[^>]*>(.*?)</pre>`)

	exportsDeployment := regexp.MustCompile(`(?m)^\s*export\s+SESAME_DEPLOYMENT=`)
	exportsFYLOBinary := regexp.MustCompile(`(?m)^\s*export\s+FYLO_BINARY=`)

	checked := 0
	for _, target := range []string{
		"README.md",
		"docs/CONFIGURATION.md",
		"docs/PROVISIONING.md",
		"docs/FEDERATION.md",
		"docs/SAML.md",
		filepath.Join("website", "client", "pages", "docs", "tac.html"),
	} {
		path := filepath.Join(root, target)
		content, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", target, err)
		}

		pattern := fenced
		if strings.HasSuffix(target, ".html") {
			pattern = preformatted
		}
		for _, block := range pattern.FindAllStringSubmatch(string(content), -1) {
			snippet := block[1]
			checked++
			if exportsDeployment.MatchString(snippet) && exportsFYLOBinary.MatchString(snippet) {
				t.Errorf("%s has a snippet exporting SESAME_DEPLOYMENT and FYLO_BINARY "+
					"together, which every runtime command refuses:\n%s", target, snippet)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no snippets were examined; the block patterns are wrong")
	}
	t.Logf("checked %d documentation snippets", checked)
}
