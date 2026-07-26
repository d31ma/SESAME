// Package runtimeid translates Go runtime identifiers into the canonical
// identifiers used at external executable boundaries.
package runtimeid

import "runtime"

// FYLOTarget returns FYLO's canonical build-target identifier for a Go
// operating system and architecture pair.
func FYLOTarget(goos, goarch string) string {
	if goos == "darwin" {
		goos = "macos"
	}
	if goarch == "amd64" {
		goarch = "x64"
	}
	return goos + "-" + goarch
}

// NativeFYLOTarget returns FYLO's canonical build-target identifier for the
// runtime that executes SESAME.
func NativeFYLOTarget() string {
	return FYLOTarget(runtime.GOOS, runtime.GOARCH)
}
