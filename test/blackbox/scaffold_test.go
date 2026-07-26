package blackbox_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCompiledBinaryVersionAndMachineContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := findRepositoryRoot(t)
	binaryName := "sesame"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)

	build := exec.Command("go", "build", "-trimpath", "-o", binaryPath, "./cmd/sesame")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build error = %v\n%s", err, output)
	}

	version := exec.Command(binaryPath, "version", "--output", "json")
	versionOutput, err := version.Output()
	if err != nil {
		t.Fatalf("sesame version error = %v", err)
	}
	var info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(versionOutput, &info); err != nil {
		t.Fatalf("version output is not JSON: %q: %v", versionOutput, err)
	}
	if info.Name != "sesame" || info.Version != "dev" {
		t.Fatalf("version output = %#v", info)
	}

	machineInput := `{"protocol_version":"1","request_id":"blackbox-1","operation":"system.ping","parameters":{}}` + "\n"
	machineCommand := exec.Command(binaryPath, "exec", "--loop")
	machineCommand.Stdin = strings.NewReader(machineInput)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	machineCommand.Stdout = &stdout
	machineCommand.Stderr = &stderr
	if err := machineCommand.Run(); err != nil {
		t.Fatalf("sesame exec error = %v; stderr = %s", err, stderr.String())
	}
	// Diagnostics are structured JSON on stderr; stdout stays protocol-only.
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var record struct {
			Level string `json:"level"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil || record.Level == "" {
			t.Fatalf("machine stderr line is not a structured log record: %q", line)
		}
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("machine stdout contains %d lines, want 1: %q", len(lines), stdout.String())
	}
	var response struct {
		RequestID string `json:"request_id"`
		OK        bool   `json:"ok"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &response); err != nil {
		t.Fatalf("machine output is not JSON: %q: %v", lines[0], err)
	}
	if response.RequestID != "blackbox-1" || !response.OK {
		t.Fatalf("machine response = %#v", response)
	}

	rejectionContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serve := exec.CommandContext(rejectionContext, binaryPath, "serve")
	var serveStdout bytes.Buffer
	var serveStderr bytes.Buffer
	serve.Stdout = &serveStdout
	serve.Stderr = &serveStderr
	err = serve.Run()
	if rejectionContext.Err() != nil {
		t.Fatalf("sesame serve did not fail immediately; a standalone listener may still exist")
	}
	if err == nil {
		t.Fatal("sesame serve succeeded, want unsupported command")
	}
	if got := serve.ProcessState.ExitCode(); got != 2 {
		t.Fatalf("sesame serve exit code = %d, want 2; stderr = %s", got, serveStderr.String())
	}
	if serveStdout.Len() != 0 {
		t.Fatalf("sesame serve stdout = %q, want empty", serveStdout.String())
	}
	if !strings.Contains(serveStderr.String(), `unknown command "serve"`) {
		t.Fatalf("sesame serve stderr = %q", serveStderr.String())
	}
}

func findRepositoryRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
