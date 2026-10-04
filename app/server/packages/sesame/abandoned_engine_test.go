package sesame

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A real engine starts FYLO as its own child. When the client gives up on an
// engine, that grandchild must not outlive the give-up: an orphaned FYLO can
// take the root after the caller has been told the deployment is busy, or
// write into a deployment the caller is already deleting.
const lingeringEngineSource = `package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var mode string

func main() {
	if len(os.Args) > 1 && os.Args[1] == "warm" {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "grandchild" {
		time.Sleep(2500 * time.Millisecond)
		_ = os.WriteFile(os.Args[2], []byte("outlived the engine"), 0o600)
		return
	}
	self, _ := os.Executable()
	marker := filepath.Join(filepath.Dir(self), "marker")
	grandchild := exec.Command(self, "grandchild", marker)
	_ = grandchild.Start()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if mode != "stubborn" {
			continue
		}
		var request struct {
			RequestID string ` + "`json:\"request_id\"`" + `
		}
		_ = jsonUnmarshal(scanner.Bytes(), &request)
		fmt.Printf("{\"protocol_version\":\"1\",\"request_id\":%q,\"ok\":true,\"result\":{\"name\":\"sesame\",\"version\":\"lingering\",\"protocol_version\":\"1\",\"operations\":[]}}\n", request.RequestID)
	}
	time.Sleep(time.Hour)
}
`

const lingeringEngineDecoder = `package main

import "encoding/json"

func jsonUnmarshal(data []byte, value any) error { return json.Unmarshal(data, value) }
`

func buildLingeringEngine(t *testing.T, mode string) (string, string) {
	t.Helper()
	workspace := t.TempDir()
	files := map[string]string{"main.go": lingeringEngineSource, "decode.go": lingeringEngineDecoder, "go.mod": "module lingering\n\ngo 1.24\n"}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(workspace, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	engine := filepath.Join(workspace, "engine")
	if runtime.GOOS == "windows" {
		engine += ".exe"
	}
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-X main.mode="+mode, "-o", engine, ".")
	build.Dir = workspace
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build lingering engine: %v\n%s", err, output)
	}
	if output, err := exec.Command(engine, "warm").CombinedOutput(); err != nil {
		t.Fatalf("warm lingering engine: %v\n%s", err, output)
	}
	return engine, filepath.Join(workspace, "marker")
}

func requireNoGrandchildOutlived(t *testing.T, marker string) {
	t.Helper()
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a process the engine started outlived the client giving up on it (marker: %v)", err)
	}
}

func TestAnAbandonedStartLeavesNoProcessBehind(t *testing.T) {
	t.Parallel()
	engine, marker := buildLingeringEngine(t, "silent")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	client, err := StartWhenAvailable(ctx, Options{Binary: engine})

	if err == nil {
		_ = client.Close()
		t.Fatal("StartWhenAvailable succeeded against an engine that never answers")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("StartWhenAvailable() error = %v, want it to wrap context.DeadlineExceeded", err)
	}
	requireNoGrandchildOutlived(t, marker)
}

func TestAnEngineKilledOnCloseLeavesNoProcessBehind(t *testing.T) {
	t.Parallel()
	engine, marker := buildLingeringEngine(t, "stubborn")
	client, err := Start(context.Background(), Options{Binary: engine})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	closeErr := client.Close()

	if closeErr == nil {
		t.Fatal("Close() reported a clean exit for an engine that ignored end of input")
	}
	requireNoGrandchildOutlived(t, marker)
}
