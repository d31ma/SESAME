package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

// runSAMLCommand drives the CLI the way an operator would.
func runSAMLCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), append([]string{"saml"}, args...),
		strings.NewReader(""), &stdout, &stderr, buildinfo.New("dev", "unknown", "unknown"))
	return code, stdout.String(), stderr.String()
}

// TestSAMLCLIRefusesBadInvocations covers every way a command line can be
// wrong before any storage is opened. Each must exit ExitUsage and say what
// is expected, rather than starting a FYLO process to find out.
func TestSAMLCLIRefusesBadInvocations(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		args    []string
		expects string
	}{
		"no subcommand": {nil, "usage: sesame saml"},
		"unknown subcommand": {
			[]string{"provider-invent"}, "usage: sesame saml"},
		// Without a deployment there is nowhere for a provider to live, and
		// the message must name the flags rather than fail obscurely later.
		"no deployment": {
			[]string{"provider-get", "--tenant-id", "ten_1", "--provider-id", "sam_1"},
			"--deployment"},
		"positional arguments": {
			[]string{"provider-get", "--deployment", "/nonexistent", "extra"},
			"unexpected positional arguments"},
		"unknown flag": {
			[]string{"provider-get", "--nonsense"}, "flag provided but not defined"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runSAMLCommand(t, testCase.args...)
			if code != ExitUsage {
				t.Fatalf("exit code = %d, want %d; stderr = %s", code, ExitUsage, stderr)
			}
			if stdout != "" {
				t.Fatalf("a usage failure wrote to stdout: %q", stdout)
			}
			if !strings.Contains(stderr, testCase.expects) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr, testCase.expects)
			}
		})
	}
}

// TestSAMLCLIListsItsSubcommands: the usage line is the only discovery
// surface a headless engine has, so every subcommand must appear in it.
func TestSAMLCLIListsItsSubcommands(t *testing.T) {
	t.Parallel()

	_, _, stderr := runSAMLCommand(t)
	for _, subcommand := range samlSubcommandNames() {
		if !strings.Contains(stderr, subcommand) {
			t.Fatalf("usage %q omits the %q subcommand", stderr, subcommand)
		}
	}
}

// TestReadCertificateFilesReadsPathsNotFlags: a certificate is public, but
// PEM on a command line is unreadable and easy to mangle, so the CLI takes
// paths.
func TestReadCertificateFilesReadsPathsNotFlags(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	first := filepath.Join(directory, "current.pem")
	second := filepath.Join(directory, "incoming.pem")
	if err := os.WriteFile(first, []byte("first"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(second, []byte("second"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Several is the normal case during a rotation, and order must survive.
	contents, err := readCertificateFiles([]string{first, second})
	if err != nil {
		t.Fatalf("readCertificateFiles() error = %v", err)
	}
	if len(contents) != 2 || contents[0] != "first" || contents[1] != "second" {
		t.Fatalf("read %#v", contents)
	}

	if _, err := readCertificateFiles(nil); err == nil {
		t.Fatal("readCertificateFiles accepted no paths")
	}
	if _, err := readCertificateFiles([]string{filepath.Join(directory, "absent.pem")}); err == nil {
		t.Fatal("readCertificateFiles accepted a path that does not exist")
	}
}
