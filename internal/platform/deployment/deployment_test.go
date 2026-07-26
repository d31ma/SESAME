package deployment

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fakeBinary(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "fylo")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestInitAndLoadRoundTrip(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "deploy")
	binary := fakeBinary(t)

	created, err := Init(dir, binary, "https://id.example")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if len(created.SnapshotKey) != SnapshotKeyBytes {
		t.Fatalf("snapshot key length = %d", len(created.SnapshotKey))
	}
	if created.Config.FYLOBinary != binary || created.FYLORoot != filepath.Join(dir, "fylo-root") {
		t.Fatalf("deployment = %#v", created)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(loaded.SnapshotKey) != string(created.SnapshotKey) {
		t.Fatal("Load() returned a different snapshot key")
	}
	if loaded.SigningKey == nil || loaded.SigningKey.ID != created.SigningKey.ID {
		t.Fatal("Load() returned a different signing key")
	}
	// The signing key stays on disk in the key directory, never in the FYLO
	// data root.
	if _, err := os.Stat(filepath.Join(dir, "keys", "signing.key")); err != nil {
		t.Fatalf("signing key is not in the key directory: %v", err)
	}

	if _, err := Init(dir, binary, "https://id.example"); err == nil {
		t.Fatal("Init() reinitialized an existing deployment")
	}
}

func TestIssuerMustBeExactlyComparable(t *testing.T) {
	t.Parallel()

	// Relying parties compare `iss` by exact string equality, so anything a
	// normalizer might rewrite is refused up front.
	for _, issuer := range []string{"", "https://id.example", "https://id.example:8443/auth"} {
		if err := ValidateIssuer(issuer); err != nil {
			t.Fatalf("ValidateIssuer(%q) = %v, want nil", issuer, err)
		}
	}
	for name, issuer := range map[string]string{
		"relative":        "/auth",
		"plain http":      "http://id.example",
		"loopback http":   "http://127.0.0.1:8080",
		"trailing slash":  "https://id.example/",
		"query":           "https://id.example?x=1",
		"fragment":        "https://id.example#x",
		"no host":         "https:///auth",
		"unknown scheme":  "urn:example:issuer",
		"control-charred": "https://id.example/\n",
	} {
		if err := ValidateIssuer(issuer); err == nil {
			t.Fatalf("ValidateIssuer accepted %s (%q)", name, issuer)
		}
	}

	dir := filepath.Join(t.TempDir(), "deploy")
	if _, err := Init(dir, fakeBinary(t), "http://id.example"); err == nil {
		t.Fatal("Init accepted a non-https issuer")
	}
}

func TestSigningKeyFailsClosed(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "deploy")
	if _, err := Init(dir, fakeBinary(t), "https://id.example"); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	keyPath := filepath.Join(dir, "keys", "signing.key")

	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("Load() with world-readable signing key error = %v", err)
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
	}

	if err := os.WriteFile(keyPath, []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load() accepted a malformed signing key")
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load() accepted a deployment with no signing key")
	}
}

func TestLoadFailsClosed(t *testing.T) {
	t.Parallel()

	binary := fakeBinary(t)

	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Load() accepted a missing deployment")
	}

	dir := filepath.Join(t.TempDir(), "deploy")
	created, err := Init(dir, binary, "https://id.example")
	if err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	keyPath := filepath.Join(dir, "keys", "snapshot.key")
	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0o644); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("Load() with world-readable key error = %v", err)
		}
		if err := os.Chmod(keyPath, 0o600); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
	}

	if err := os.WriteFile(keyPath, []byte("too-short\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load() accepted a malformed snapshot key")
	}

	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"config_version":2,"fylo_binary":"`+created.Config.FYLOBinary+`"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load() accepted an unsupported configuration version")
	}

	if err := os.WriteFile(configPath, []byte(`{"config_version":1,"fylo_binary":"relative/fylo"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load() accepted a relative FYLO binary path")
	}
}

// TestLoadNamesWhatIsWrongAndHowToFixIt: the raw open error ("no such file
// ... config.json") tells an operator neither which of the two problems they
// have nor what to run. Both remedies differ, so both messages must.
func TestLoadNamesWhatIsWrongAndHowToFixIt(t *testing.T) {
	t.Parallel()

	t.Run("a directory that does not exist", func(t *testing.T) {
		t.Parallel()

		missing := filepath.Join(t.TempDir(), "not-created")
		_, err := Load(missing)
		if err == nil {
			t.Fatal("Load accepted a directory that does not exist")
		}
		for _, expected := range []string{missing, "does not exist", "sesame init"} {
			if !strings.Contains(err.Error(), expected) {
				t.Errorf("error %q does not mention %q", err, expected)
			}
		}
	})

	t.Run("a directory that was never initialised", func(t *testing.T) {
		t.Parallel()

		empty := t.TempDir()
		_, err := Load(empty)
		if err == nil {
			t.Fatal("Load accepted an uninitialised directory")
		}
		for _, expected := range []string{empty, "not a SESAME deployment", "sesame init"} {
			if !strings.Contains(err.Error(), expected) {
				t.Errorf("error %q does not mention %q", err, expected)
			}
		}
	})

	t.Run("a path that is a file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "deployment")
		if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("error = %v, want it to say the path is not a directory", err)
		}
	})
}
