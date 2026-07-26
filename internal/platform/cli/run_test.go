package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

func TestRunVersionJSON(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{"version", "--output", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		buildinfo.New("1.2.3", "abc123", "2026-07-23T00:00:00Z"),
	)

	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr = %s", exitCode, ExitSuccess, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	var info buildinfo.Info
	if err := json.Unmarshal(stdout.Bytes(), &info); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if info.Version != "1.2.3" {
		t.Fatalf("version = %q, want 1.2.3", info.Version)
	}
}

func TestRunExecLoopKeepsStdoutMachineReadable(t *testing.T) {
	t.Parallel()

	stdin := strings.NewReader(`{"protocol_version":"1","request_id":"ping-1","operation":"system.ping","parameters":{}}` + "\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{"exec", "--loop"},
		stdin,
		&stdout,
		&stderr,
		buildinfo.New("dev", "unknown", "unknown"),
	)

	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d, want %d; stderr = %s", exitCode, ExitSuccess, stderr.String())
	}
	// Diagnostics go to stderr as structured JSON; stdout stays protocol-only.
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		var record struct {
			Level string `json:"level"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil || record.Level == "" {
			t.Fatalf("stderr line is not a structured log record: %q", line)
		}
	}

	var response struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
		t.Fatalf("stdout is not one JSON response: %q: %v", stdout.String(), err)
	}
	if !response.OK {
		t.Fatalf("response = %s, want ok", stdout.String())
	}
}

func TestRunRejectsUnknownCommands(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{"unknown"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		buildinfo.New("", "", ""),
	)

	if exitCode != ExitUsage {
		t.Fatalf("exit code = %d, want %d", exitCode, ExitUsage)
	}
	if !strings.Contains(stderr.String(), `unknown command "unknown"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunRejectsStandaloneServeCommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{"serve", "unexpected"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		buildinfo.New("", "", ""),
	)

	if exitCode != ExitUsage {
		t.Fatalf("exit code = %d, want %d", exitCode, ExitUsage)
	}
	if !strings.Contains(stderr.String(), `unknown command "serve"`) {
		t.Fatalf("stderr = %q, want serve to be rejected as an unknown command", stderr.String())
	}
	if strings.Contains(stderr.String(), "sesame serve [") {
		t.Fatalf("usage advertises a standalone server: %q", stderr.String())
	}
}
