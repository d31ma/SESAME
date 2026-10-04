package sesame

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func lockedOptions(t *testing.T, rootName string) Options {
	t.Helper()

	workspace := t.TempDir()
	fakeFYLO := buildFakeFYLO(t, workspace)
	root := filepath.Join(workspace, rootName)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	return Options{Binary: testBinary, FYLOBinary: fakeFYLO, FYLORoot: root}
}

func TestStartReportsALockedDeploymentAsTyped(t *testing.T) {
	client, err := Start(context.Background(), lockedOptions(t, "root-locked"))
	if err == nil {
		_ = client.Close()
		t.Fatal("Start succeeded against a root another owner holds")
	}
	if !errors.Is(err, ErrDeploymentLocked) {
		t.Fatalf("Start() error = %v, want ErrDeploymentLocked", err)
	}
}

func TestStartDoesNotCallOtherFailuresLocked(t *testing.T) {
	_, err := Start(context.Background(), Options{
		Binary:     testBinary,
		Deployment: filepath.Join(t.TempDir(), "not-created"),
	})
	if err == nil || errors.Is(err, ErrDeploymentLocked) {
		t.Fatalf("Start() error = %v, want a failure that is not ErrDeploymentLocked", err)
	}
}

func TestStartWhenAvailableGivesUpWhenTheContextEnds(t *testing.T) {
	options := lockedOptions(t, "root-locked")
	wait := 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	started := time.Now()
	client, err := StartWhenAvailable(ctx, options)
	waited := time.Since(started)

	if err == nil {
		_ = client.Close()
		t.Fatal("StartWhenAvailable succeeded against a root another owner holds")
	}
	if !errors.Is(err, ErrDeploymentLocked) {
		t.Fatalf("StartWhenAvailable() error = %v, want ErrDeploymentLocked", err)
	}
	if waited < wait || waited > testOperationTimeout {
		t.Fatalf("StartWhenAvailable() waited %v, want between %v and %v", waited, wait, testOperationTimeout)
	}
}

func TestStartWhenAvailableStartsAFreeDeployment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	client, err := StartWhenAvailable(ctx, lockedOptions(t, "root"))
	if err != nil {
		t.Fatalf("StartWhenAvailable() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
}
