package contract_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The README is the front page, and it is the one honesty surface no other
// test covered. It had drifted four phases behind the code — claiming no
// identity protocol was implemented while the engine shipped an OIDC
// provider, passkeys, SAML, and SCIM — because nothing failed when it did.
//
// These checks are deliberately narrow: countable claims and local links.
// Prose still needs a human, but prose is not what silently goes stale.

func loadREADME(t *testing.T) (string, string) {
	t.Helper()

	root := repositoryRoot(t)
	content, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	return string(content), root
}

// TestREADMEOperationCountMatchesTheManifest.
func TestREADMEOperationCountMatchesTheManifest(t *testing.T) {
	t.Parallel()

	readme, _ := loadREADME(t)
	loaded, _ := loadManifest(t)

	match := regexp.MustCompile(`(\d+) operations across`).FindStringSubmatch(readme)
	if match == nil {
		t.Fatal("the README no longer states an operation count")
	}
	claimed, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("operation count is not a number: %v", err)
	}
	if claimed != len(loaded.Operations) {
		t.Fatalf("the README claims %d operations; the manifest defines %d",
			claimed, len(loaded.Operations))
	}
}

// TestREADMELinksResolve: a front page full of 404s reads as an abandoned
// project, and every one of these is a path that a moved file breaks.
func TestREADMELinksResolve(t *testing.T) {
	t.Parallel()

	readme, root := loadREADME(t)
	links := regexp.MustCompile(`\]\(([^)]+)\)`).FindAllStringSubmatch(readme, -1)
	links = append(links, regexp.MustCompile(`href="([^"]+)"`).FindAllStringSubmatch(readme, -1)...)
	if len(links) == 0 {
		t.Fatal("the README contains no links")
	}

	checked := 0
	for _, link := range links {
		target := link[1]
		if strings.HasPrefix(target, "http") || strings.HasPrefix(target, "#") {
			continue
		}
		checked++
		path := filepath.Join(root, filepath.FromSlash(strings.SplitN(target, "#", 2)[0]))
		if _, err := os.Stat(path); err != nil {
			t.Errorf("the README links to %s, which does not exist", target)
		}
	}
	t.Logf("checked %d local links", checked)
}

// TestREADMEDescribesEveryShippedSDK: the table is how a developer finds the
// file to copy, so a shipped shim missing from it is effectively unreleased.
func TestREADMEDescribesEveryShippedSDK(t *testing.T) {
	t.Parallel()

	readme, root := loadREADME(t)
	entries, err := os.ReadDir(filepath.Join(root, "clients"))
	if err != nil {
		t.Fatalf("read clients: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !strings.Contains(readme, "clients/"+entry.Name()) {
			t.Errorf("clients/%s ships, but the README never links it", entry.Name())
		}
	}
}

// TestREADMEMakesNoUnearnedSupportClaim mirrors the guard the website carries.
// The front page is the likeliest place for a claim to creep in.
func TestREADMEMakesNoUnearnedSupportClaim(t *testing.T) {
	t.Parallel()

	readme, _ := loadREADME(t)
	lowered := strings.ToLower(readme)
	for _, phrase := range []string{
		"openid certified",
		"production ready",
		"production-ready",
		"enterprise ready",
		"enterprise-grade",
		"battle tested",
		"battle-tested",
		"fully compliant",
	} {
		// "not OpenID certified" is the honest form and has to stay legal.
		for _, index := range regexp.MustCompile(regexp.QuoteMeta(phrase)).
			FindAllStringIndex(lowered, -1) {
			start := index[0] - 12
			if start < 0 {
				start = 0
			}
			if strings.Contains(lowered[start:index[0]], "not ") {
				continue
			}
			t.Errorf("the README claims %q, which SESAME has not earned", phrase)
		}
	}
}
