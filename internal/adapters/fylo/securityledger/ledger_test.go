package securityledger

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/domain/tenant"
)

var fakeFYLOBinary string

func TestMain(m *testing.M) {
	temporaryDirectory, err := os.MkdirTemp("", "sesame-fake-fylo-ledger-*")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create fake FYLO directory: %v\n", err)
		os.Exit(1)
	}

	binaryName := "fake-fylo"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	fakeFYLOBinary = filepath.Join(temporaryDirectory, binaryName)

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		_, _ = fmt.Fprintln(os.Stderr, "locate security ledger test file")
		os.Exit(1)
	}
	packageDirectory := filepath.Dir(filename)
	build := exec.Command("go", "build", "-trimpath", "-o", fakeFYLOBinary, "../testdata/fakefylo")
	build.Dir = packageDirectory
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build fake FYLO binary: %v\n%s", buildErr, output)
		os.Exit(1)
	}

	exitCode := m.Run()
	_ = os.RemoveAll(temporaryDirectory)
	os.Exit(exitCode)
}

func startClient(t *testing.T, root string) *fyloadapter.Client {
	t.Helper()

	client, err := fyloadapter.Start(context.Background(), fyloadapter.Config{
		Binary:             fakeFYLOBinary,
		Root:               root,
		ExpectedProtocol:   fyloadapter.ProtocolVersion,
		MaxRequestBytes:    1 << 16,
		MaxResponseBytes:   1 << 20,
		MaxDiagnosticBytes: 1024,
		ShutdownTimeout:    250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestLedgerAppendsAndSurvivesRestart(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "normal")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	client := startClient(t, root)
	ledger, events, err := Open(context.Background(), client)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("Open(empty root) replayed %d events, want 0", len(events))
	}

	for index := range 3 {
		event, err := ledger.Append(
			context.Background(),
			tenant.EventBootstrapped,
			fmt.Sprintf("tnt_%032d", index),
			"test",
			map[string]any{"n": index},
		)
		if err != nil {
			t.Fatalf("Append(%d) error = %v", index, err)
		}
		if event.Sequence != int64(index)+1 {
			t.Fatalf("Append(%d) sequence = %d", index, event.Sequence)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	restarted := startClient(t, root)
	_, replayed, err := Open(context.Background(), restarted)
	if err != nil {
		t.Fatalf("Open(restarted) error = %v", err)
	}
	if len(replayed) != 3 {
		t.Fatalf("replay produced %d events, want 3", len(replayed))
	}
	for index, event := range replayed {
		if event.Sequence != int64(index)+1 || event.Type != tenant.EventBootstrapped {
			t.Fatalf("replayed event %d = %#v", index, event)
		}
	}

	// The restarted ledger continues the same chain.
	appendAfterRestart, _, err := Open(context.Background(), restarted)
	if err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	event, err := appendAfterRestart.Append(
		context.Background(),
		tenant.EventBootstrapped,
		"tnt_after",
		"test",
		map[string]any{"n": 3},
	)
	if err != nil {
		t.Fatalf("Append(after restart) error = %v", err)
	}
	if event.Sequence != 4 || event.PreviousHash != replayed[2].Hash {
		t.Fatalf("post-restart event = %#v", event)
	}
}

func TestSnapshotBoundsReplayAndFailsClosedOnTamper(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "normal")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}

	client := startClient(t, root)
	ledger, replayed, err := OpenVerified(context.Background(), client, key)
	if err != nil {
		t.Fatalf("OpenVerified() error = %v", err)
	}
	if replayed.SnapshotState != nil || len(replayed.TailEvents) != 0 {
		t.Fatalf("fresh OpenVerified() replay = %#v", replayed)
	}
	if err := ledger.WriteSnapshot(context.Background(), map[string]any{"snapshot": "empty"}); err != nil {
		t.Fatalf("WriteSnapshot(empty) error = %v", err)
	}

	for index := range 2 {
		if _, err := ledger.Append(
			context.Background(),
			tenant.EventBootstrapped,
			fmt.Sprintf("tnt_%032d", index),
			"test",
			map[string]any{"n": index},
		); err != nil {
			t.Fatalf("Append(%d) error = %v", index, err)
		}
	}
	if err := ledger.WriteSnapshot(context.Background(), map[string]any{"snapshot": "two"}); err != nil {
		t.Fatalf("WriteSnapshot(2) error = %v", err)
	}
	if _, err := ledger.Append(
		context.Background(),
		tenant.EventBootstrapped,
		"tnt_tail",
		"test",
		map[string]any{"n": 2},
	); err != nil {
		t.Fatalf("Append(tail) error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Reopen with the key: the newest snapshot bounds replay to one tail
	// event.
	restarted := startClient(t, root)
	_, bounded, err := OpenVerified(context.Background(), restarted, key)
	if err != nil {
		t.Fatalf("restart OpenVerified() error = %v", err)
	}
	if bounded.SnapshotSequence != 2 || len(bounded.TailEvents) != 1 || bounded.SnapshotsStored != 2 {
		t.Fatalf("bounded replay = %#v", bounded)
	}
	if string(bounded.SnapshotState) != `{"snapshot":"two"}` {
		t.Fatalf("snapshot state = %s", bounded.SnapshotState)
	}
	if bounded.TailEvents[0].Sequence != 3 {
		t.Fatalf("tail event = %#v", bounded.TailEvents[0])
	}

	// A wrong key fails closed rather than silently falling back.
	wrongKey := make([]byte, 32)
	if _, _, err := OpenVerified(context.Background(), restarted, wrongKey); err == nil {
		t.Fatal("OpenVerified() accepted snapshots with a wrong MAC key")
	}

	// Without a key, snapshots are ignored and the full chain replays.
	_, full, err := OpenVerified(context.Background(), restarted, nil)
	if err != nil {
		t.Fatalf("keyless OpenVerified() error = %v", err)
	}
	if full.SnapshotState != nil || len(full.TailEvents) != 3 {
		t.Fatalf("keyless replay = %#v", full)
	}
	if err := restarted.Close(); err != nil {
		t.Fatalf("restarted Close() error = %v", err)
	}

	// Tamper with the stored snapshot state on disk: reopening with the key
	// must fail closed.
	storePath := filepath.Join(root, "fake-store.json")
	stored, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// The state is stored as an escaped JSON string inside the document.
	tampered := bytes.Replace(stored, []byte(`{\"snapshot\":\"two\"}`), []byte(`{\"snapshot\":\"lie\"}`), 1)
	if bytes.Equal(tampered, stored) {
		t.Fatal("tamper substitution did not change the stored snapshot")
	}
	if err := os.WriteFile(storePath, tampered, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	tamperedClient := startClient(t, root)
	if _, _, err := OpenVerified(context.Background(), tamperedClient, key); err == nil {
		t.Fatal("OpenVerified() accepted a tampered snapshot")
	}
}
