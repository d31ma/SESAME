package cli

import (
	"strings"
	"testing"
)

func TestParseInitializationEnvironment(t *testing.T) {
	t.Parallel()

	values, err := parseInitializationEnvironment(strings.NewReader(strings.Join([]string{
		"# SESAME initialization",
		"export SESAME_DEPLOYMENT='./deployment path'",
		`FYLO_BINARY="/opt/fylo binary"`,
		"SESAME_ISSUER=https://id.example.com # public issuer",
		"APPLICATION_SETTING=value-with-#-fragment",
	}, "\r\n")))
	if err != nil {
		t.Fatalf("parse initialization environment: %v", err)
	}

	want := map[string]string{
		EnvDeployment:           "./deployment path",
		EnvFYLOBinary:           "/opt/fylo binary",
		EnvInitializationIssuer: "https://id.example.com",
		"APPLICATION_SETTING":   "value-with-#-fragment",
	}
	for name, expected := range want {
		if values[name] != expected {
			t.Errorf("%s = %q, want %q", name, values[name], expected)
		}
	}
}

func TestParseInitializationEnvironmentBoundsInput(t *testing.T) {
	t.Parallel()

	oversized := strings.Repeat("A", maxInitializationEnvironmentBytes+1)
	if _, err := parseInitializationEnvironment(strings.NewReader(oversized)); err == nil {
		t.Fatal("oversized environment file was accepted")
	}
}

func TestParseInitializationEnvironmentRefusesAmbiguity(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing assignment": "SESAME_DEPLOYMENT",
		"invalid name":       "SESAME-DEPLOYMENT=./deploy",
		"duplicate name":     "FYLO_BINARY=/one\nFYLO_BINARY=/two",
		"unterminated quote": `SESAME_ISSUER="https://id.example.com`,
		"trailing content":   `FYLO_BINARY="/opt/fylo" surprise`,
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseInitializationEnvironment(strings.NewReader(contents)); err == nil {
				t.Fatal("parse succeeded, want a fail-closed error")
			}
		})
	}
}

func FuzzParseInitializationEnvironment(f *testing.F) {
	for _, seed := range []string{
		"",
		"SESAME_DEPLOYMENT=./deploy\nFYLO_BINARY=/opt/fylo\n",
		"export SESAME_ISSUER='https://id.example.com' # comment\n",
		"FYLO_BINARY=\x00",
		`FYLO_BINARY="C:\Program Files\FYLO\fylo.exe"`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, contents string) {
		_, _ = parseInitializationEnvironment(strings.NewReader(contents))
	})
}
