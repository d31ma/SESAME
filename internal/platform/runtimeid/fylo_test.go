package runtimeid

import (
	"runtime"
	"testing"
)

func TestFYLOTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		goos   string
		goarch string
		want   string
	}{
		{name: "macOS x64", goos: "darwin", goarch: "amd64", want: "macos-x64"},
		{name: "macOS ARM64", goos: "darwin", goarch: "arm64", want: "macos-arm64"},
		{name: "Linux x64", goos: "linux", goarch: "amd64", want: "linux-x64"},
		{name: "Linux ARM64", goos: "linux", goarch: "arm64", want: "linux-arm64"},
		{name: "Windows x64", goos: "windows", goarch: "amd64", want: "windows-x64"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := FYLOTarget(test.goos, test.goarch); got != test.want {
				t.Fatalf("FYLOTarget(%q, %q) = %q, want %q", test.goos, test.goarch, got, test.want)
			}
		})
	}
}

func TestNativeFYLOTarget(t *testing.T) {
	t.Parallel()

	want := FYLOTarget(runtime.GOOS, runtime.GOARCH)
	if got := NativeFYLOTarget(); got != want {
		t.Fatalf("NativeFYLOTarget() = %q, want %q", got, want)
	}
}
