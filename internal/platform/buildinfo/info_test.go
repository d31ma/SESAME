package buildinfo

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestNewUsesSafeDevelopmentDefaults(t *testing.T) {
	t.Parallel()

	info := New("", "", "")

	if info.Name != "sesame" {
		t.Fatalf("Name = %q, want sesame", info.Name)
	}
	if info.Version != "dev" {
		t.Fatalf("Version = %q, want dev", info.Version)
	}
	if info.Commit != "unknown" {
		t.Fatalf("Commit = %q, want unknown", info.Commit)
	}
	if info.BuiltAt != "unknown" {
		t.Fatalf("BuiltAt = %q, want unknown", info.BuiltAt)
	}
	if info.GoVersion != runtime.Version() {
		t.Fatalf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
	if info.OS != runtime.GOOS || info.Arch != runtime.GOARCH {
		t.Fatalf("target = %s/%s, want %s/%s", info.OS, info.Arch, runtime.GOOS, runtime.GOARCH)
	}
}

func TestInfoHasStableJSONFieldNames(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(New("1.2.3", "abc123", "2026-07-23T00:00:00Z"))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	want := `{"name":"sesame","version":"1.2.3","commit":"abc123","built_at":"2026-07-23T00:00:00Z","go_version":"` + runtime.Version() + `","os":"` + runtime.GOOS + `","arch":"` + runtime.GOARCH + `"}`
	if string(encoded) != want {
		t.Fatalf("Marshal() = %s, want %s", encoded, want)
	}
}
