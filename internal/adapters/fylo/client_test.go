package fylo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var fakeFYLOBinary string

func TestMain(m *testing.M) {
	temporaryDirectory, err := os.MkdirTemp("", "sesame-fake-fylo-*")
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
		_, _ = fmt.Fprintln(os.Stderr, "locate FYLO adapter test file")
		os.Exit(1)
	}
	packageDirectory := filepath.Dir(filename)
	build := exec.Command("go", "build", "-trimpath", "-o", fakeFYLOBinary, "./testdata/fakefylo")
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

func TestClientValidatesProtocolAndCorrelatesResponses(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "normal"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	})

	var result struct {
		Collection string `json:"collection"`
		Exists     bool   `json:"exists"`
	}
	if err := client.Request(
		context.Background(),
		"inspectCollection",
		map[string]any{"collection": "security_events"},
		&result,
	); err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if result.Collection != "security_events" || !result.Exists {
		t.Fatalf("result = %#v", result)
	}
	if client.ProtocolVersion() != ProtocolVersion {
		t.Fatalf("ProtocolVersion() = %d, want %d", client.ProtocolVersion(), ProtocolVersion)
	}
	identity := client.Identity()
	if identity.RuntimeVersion != PhaseOneRuntimeVersion {
		t.Fatalf("Identity().RuntimeVersion = %q, want %q", identity.RuntimeVersion, PhaseOneRuntimeVersion)
	}
	if !identity.Capabilities.Handshake || !identity.Capabilities.ExclusiveRoot {
		t.Fatalf("Identity().Capabilities = %#v", identity.Capabilities)
	}
	if identity.Machine.MaxRequestBytes != 1024 || identity.Machine.MaxResponseBytes != 4096 {
		t.Fatalf("Identity().Machine = %#v", identity.Machine)
	}
}

func TestStartFailsClosedOnProtocolMismatch(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "protocol-mismatch"))
	if client != nil {
		_ = client.Close()
		t.Fatal("Start() client is non-nil after protocol mismatch")
	}
	var compatibilityError *CompatibilityError
	if !errors.As(err, &compatibilityError) {
		t.Fatalf("Start() error = %T %v, want *CompatibilityError", err, err)
	}
	if compatibilityError.Expected != ProtocolVersion || compatibilityError.Actual != 2 {
		t.Fatalf("compatibility error = %#v", compatibilityError)
	}
}

func TestStartRejectsIncompatibleRuntimeIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode string
	}{
		{name: "runtime version", mode: "runtime-mismatch"},
		{name: "build target", mode: "target-mismatch"},
		{name: "request frame limit", mode: "frame-mismatch"},
		{name: "missing identity field", mode: "identity-missing-field"},
		{name: "handshake capability", mode: "missing-handshake"},
		{name: "exclusive root capability", mode: "missing-exclusive-root"},
		{name: "query pagination capability", mode: "missing-pagination"},
		{name: "vendor dependency", mode: "missing-vendor"},
		{name: "development build", mode: "development"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client, err := Start(context.Background(), testConfig(t, test.mode))
			if client != nil {
				_ = client.Close()
				t.Fatal("Start() client is non-nil after identity mismatch")
			}
			var identityError *RuntimeCompatibilityError
			if !errors.As(err, &identityError) {
				t.Fatalf("Start() error = %T %v, want *RuntimeCompatibilityError", err, err)
			}
		})
	}
}

func TestStartAllowsExplicitDevelopmentBuild(t *testing.T) {
	t.Parallel()

	config := testConfig(t, "development")
	config.AllowDevelopmentBuild = true
	client, err := Start(context.Background(), config)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Close()
	if client.Identity().BuildKind != "development-compiled" {
		t.Fatalf("Identity().BuildKind = %q", client.Identity().BuildKind)
	}
}

func TestStartReturnsTypedExclusiveRootFailure(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "root-locked"))
	if client != nil {
		_ = client.Close()
		t.Fatal("Start() client is non-nil after root lease failure")
	}
	var operationError *OperationError
	if !errors.As(err, &operationError) {
		t.Fatalf("Start() error = %T %v, want *OperationError", err, err)
	}
	if operationError.Code != "EROOTLOCKED" {
		t.Fatalf("OperationError.Code = %q, want EROOTLOCKED", operationError.Code)
	}
}

func TestClientRejectsAmbiguousAndOversizedResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode string
	}{
		{name: "duplicate fields", mode: "duplicate"},
		{name: "oversized frame", mode: "oversized"},
		{name: "malformed JSON", mode: "malformed"},
		{name: "unknown field", mode: "unknown"},
		{name: "missing required field", mode: "missing-duration"},
		{name: "null required field", mode: "null-duration"},
		{name: "operation mismatch", mode: "operation-mismatch"},
		{name: "request ID mismatch", mode: "request-mismatch"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client, err := Start(context.Background(), testConfig(t, test.mode))
			if client != nil {
				_ = client.Close()
			}
			if err == nil {
				t.Fatal("Start() error = nil, want fail-closed protocol error")
			}
		})
	}
}

func TestClientReturnsTypedOperationErrors(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "normal"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	var result map[string]any
	err = client.Request(context.Background(), "fail", nil, &result)
	var operationError *OperationError
	if !errors.As(err, &operationError) {
		t.Fatalf("Request() error = %T %v, want *OperationError", err, err)
	}
	if operationError.Operation != "fail" || operationError.Code != "EFAIL" {
		t.Fatalf("operation error = %#v", operationError)
	}
}

func TestCancellationTerminatesBlockedChild(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "block"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	requestContext, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var result map[string]any
	err = client.Request(requestContext, "block", nil, &result)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Request() error = %T %v, want context deadline", err, err)
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatalf("Close() after cancellation error = %v", closeErr)
	}
}

func TestQueuedRequestHonorsItsOwnCancellation(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "block"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// The head-of-line request is given a deadline far longer than the queued
	// one's. The property under test is that the queued request observes its
	// own cancellation instead of waiting for the request ahead of it, and a
	// wide gap states that relatively rather than as a wall-clock bound that
	// scheduling delay under -race can breach.
	firstContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() {
		var result map[string]any
		firstDone <- client.Request(firstContext, "block", nil, &result)
	}()

	deadline := time.Now().Add(time.Second)
	for !strings.Contains(client.Diagnostics(), "block-started") {
		if time.Now().After(deadline) {
			t.Fatal("first request did not reach the fake FYLO child")
		}
		time.Sleep(time.Millisecond)
	}
	secondContext, cancelSecond := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancelSecond()
	var result map[string]any
	err = client.Request(secondContext, "inspectCollection", map[string]any{
		"collection": "security-events",
	}, &result)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued Request() error = %T %v, want context deadline", err, err)
	}
	// The request ahead of it is still in flight: the queued one did not wait
	// for it. This is the assertion the wall-clock bound was standing in for.
	select {
	case firstErr := <-firstDone:
		t.Fatalf("the head-of-line request finished first with %v; "+
			"the queued request waited for it rather than for its own deadline", firstErr)
	default:
	}

	cancelFirst()
	if firstErr := <-firstDone; !errors.Is(firstErr, context.Canceled) {
		t.Fatalf("first Request() error = %T %v, want context cancellation", firstErr, firstErr)
	}
	if closeErr := client.Close(); closeErr != nil {
		t.Fatalf("Close() after cancellation error = %v", closeErr)
	}
}

func TestAlreadyCancelledRequestDoesNotTerminateChild(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "normal"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	var result map[string]any
	err = client.Request(cancelled, "inspectCollection", map[string]any{
		"collection": "security-events",
	}, &result)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Request() error = %T %v, want context.Canceled", err, err)
	}

	err = client.Request(context.Background(), "inspectCollection", map[string]any{
		"collection": "security-events",
	}, &result)
	if err != nil {
		t.Fatalf("Request() after cancellation error = %v", err)
	}
}

func TestCrashTerminatesChild(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "normal"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := client.Crash(); err != nil {
		t.Fatalf("Crash() error = %v", err)
	}

	var result map[string]any
	err = client.Request(context.Background(), "inspectCollection", map[string]any{
		"collection": "security-events",
	}, &result)
	if err == nil {
		t.Fatal("Request() succeeded after Crash()")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() after Crash() error = %v", err)
	}
}

func TestCloseBoundsUncooperativeChildShutdown(t *testing.T) {
	t.Parallel()

	config := testConfig(t, "stubborn")
	config.ShutdownTimeout = 50 * time.Millisecond
	client, err := Start(context.Background(), config)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	started := time.Now()
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Close() took %s, want a bounded shutdown", elapsed)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestClientDrainsAndBoundsDiagnostics(t *testing.T) {
	t.Parallel()

	config := testConfig(t, "stderr")
	config.MaxDiagnosticBytes = 256
	client, err := Start(context.Background(), config)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Close()

	var diagnostics string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		diagnostics = client.Diagnostics()
		if strings.Contains(diagnostics, "diagnostic-tail") {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(diagnostics) > config.MaxDiagnosticBytes {
		t.Fatalf("diagnostics length = %d, want <= %d", len(diagnostics), config.MaxDiagnosticBytes)
	}
	if !strings.Contains(diagnostics, "diagnostic-tail") {
		t.Fatalf("diagnostics do not retain tail: %q", diagnostics)
	}
}

func TestFindDocsPageTraversesBoundedPages(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "normal"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	capability := client.Identity().Capabilities.QueryPagination
	if capability == nil || capability.MaxItems != 4096 {
		t.Fatalf("Identity().Capabilities.QueryPagination = %#v", capability)
	}

	query := map[string]any{"$ops": []any{}}
	collected := map[string]json.RawMessage{}
	cursor := ""
	pages := 0
	for {
		page, err := client.FindDocsPage(context.Background(), "security-events", query, 5, cursor)
		if err != nil {
			t.Fatalf("FindDocsPage() error = %v", err)
		}
		pages++
		if len(page.Items) > 5 {
			t.Fatalf("page %d returned %d items over the limit", pages, len(page.Items))
		}
		for id, document := range page.Items {
			if _, exists := collected[id]; exists {
				t.Fatalf("document %s appeared on more than one page", id)
			}
			collected[id] = document
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if pages != 3 || len(collected) != 13 {
		t.Fatalf("traversal produced %d pages and %d documents, want 3 and 13", pages, len(collected))
	}
}

func TestFindDocsPageReturnsTypedInvalidCursor(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "normal"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	query := map[string]any{"$ops": []any{}}
	_, err = client.FindDocsPage(context.Background(), "security-events", query, 5, "bogus-cursor")
	if !IsInvalidCursor(err) {
		t.Fatalf("FindDocsPage() error = %T %v, want typed EINVALIDCURSOR", err, err)
	}
	if IsInvalidCursor(errors.New("unrelated")) {
		t.Fatal("IsInvalidCursor() accepted an unrelated error")
	}
}

func TestFindDocsPageValidatesLimitLocally(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "normal"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	query := map[string]any{"$ops": []any{}}
	for _, limit := range []int{0, -1, 4097} {
		if _, err := client.FindDocsPage(context.Background(), "security-events", query, limit, ""); err == nil {
			t.Fatalf("FindDocsPage() accepted limit %d", limit)
		}
	}
}

func TestFindDocsPageFailsClosedOnInconsistentPages(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"page-miscount", "page-overflow"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			client, err := Start(context.Background(), testConfig(t, mode))
			if err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			t.Cleanup(func() { _ = client.Close() })

			query := map[string]any{"$ops": []any{}}
			if _, err := client.FindDocsPage(context.Background(), "security-events", query, 5, ""); err == nil {
				t.Fatal("FindDocsPage() accepted an inconsistent page")
			}
		})
	}
}

func TestRequestRejectsReservedFields(t *testing.T) {
	t.Parallel()

	client, err := Start(context.Background(), testConfig(t, "normal"))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Close()

	for _, field := range []string{"op", "requestId", "root"} {
		var result json.RawMessage
		err := client.Request(context.Background(), "inspectCollection", map[string]any{field: "override"}, &result)
		if err == nil {
			t.Fatalf("Request() accepted reserved field %q", field)
		}
	}
}

func FuzzDecodeResponseNeverPanics(f *testing.F) {
	f.Add([]byte(`{"protocolVersion":1,"ok":true,"op":"inspectCollection","requestId":"abc","durationMs":0,"result":{}}`))
	f.Add([]byte(`{"ok":true,"ok":false}`))
	f.Add([]byte("{not-json"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, frame []byte) {
		_, _ = decodeResponse(frame)
	})
}

func FuzzDecodeRuntimeIdentityNeverPanics(f *testing.F) {
	f.Add([]byte(`{"runtimeVersion":"26.30.05","protocolVersion":1,"commit":"abc","buildTarget":"macos-arm64","buildKind":"release","dependencies":{"chex":{"requiredVersion":"26.28.02","available":true},"ttid":{"requiredVersion":"26.28.02","available":true}},"machine":{"framing":"ndjson","encoding":"utf-8","delimiter":"LF","delimiterCountsTowardLimit":false,"maxRequestBytes":1048576,"maxResponseBytes":8388608,"duplicateKeys":"rejected","truncatedFrame":"error-and-terminate","malformedFrame":"error-and-resume-at-next-LF"},"capabilities":{"handshake":true,"exclusiveRoot":true,"queryPagination":{"version":1,"operations":["findDocs","findDeletedDocs"],"defaultItems":256,"maxItems":4096,"ordering":"ttid-binary-ascending","restartPolicy":"restart-from-first-page"}}}`))
	// The v26.30.06 handshake verbatim. It carries pagination fields and a
	// wholeRootBackup capability the adapter does not read; seeding the real
	// shape keeps a future field addition from being the first thing that
	// reaches the decoder unfuzzed.
	f.Add([]byte(`{"runtimeVersion":"26.30.06","protocolVersion":1,"commit":"39f57b5cf3120c9b9b3b4ead9e749b47b76ac4f0","buildTarget":"macos-arm64","buildKind":"release","dependencies":{"chex":{"requiredVersion":"26.28.02","available":true},"ttid":{"requiredVersion":"26.28.02","available":true}},"machine":{"framing":"ndjson","encoding":"utf-8","delimiter":"LF","delimiterCountsTowardLimit":false,"maxRequestBytes":1048576,"maxResponseBytes":8388608,"duplicateKeys":"rejected","truncatedFrame":"error-and-terminate","malformedFrame":"error-and-resume-at-next-LF"},"capabilities":{"handshake":true,"exclusiveRoot":true,"queryPagination":{"version":1,"operations":["findDocs","findDeletedDocs"],"defaultItems":256,"maxItems":4096,"maxSnapshotBytes":1073741824,"cursorTtlMs":900000,"ordering":"ttid-binary-ascending","scope":"persistent-process","restartPolicy":"restart-from-first-page","mutationPolicy":"snapshot-at-first-page"},"wholeRootBackup":{"version":1,"available":true,"configured":false,"machineOperations":["backupStatus","backupReconcile"],"offlineOperations":["backup verify","backup restore"],"metadataFormat":"fylo.posix.v2"}}}`))
	f.Add([]byte(`{"capabilities":{"handshake":true,"exclusiveRoot":true}}`))
	f.Add([]byte(`{"runtimeVersion":null}`))
	f.Add([]byte("{not-json"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, identity []byte) {
		_, _ = decodeRuntimeIdentity(identity)
	})
}

// TestDecodeRealV26_30_06Handshake pins that the adapter accepts the pinned
// release's handshake verbatim, including the capability fields it does not
// read. A decoder that rejected unknown fields would break on every FYLO
// release that adds one.
func TestDecodeRealV26_30_06Handshake(t *testing.T) {
	t.Parallel()

	const handshake = `{"runtimeVersion":"26.30.06","protocolVersion":1,"commit":"39f57b5cf3120c9b9b3b4ead9e749b47b76ac4f0","buildTarget":"macos-arm64","buildKind":"release","dependencies":{"chex":{"requiredVersion":"26.28.02","available":true},"ttid":{"requiredVersion":"26.28.02","available":true}},"machine":{"framing":"ndjson","encoding":"utf-8","delimiter":"LF","delimiterCountsTowardLimit":false,"maxRequestBytes":1048576,"maxResponseBytes":8388608,"duplicateKeys":"rejected","truncatedFrame":"error-and-terminate","malformedFrame":"error-and-resume-at-next-LF"},"capabilities":{"handshake":true,"exclusiveRoot":true,"queryPagination":{"version":1,"operations":["findDocs","findDeletedDocs"],"defaultItems":256,"maxItems":4096,"maxSnapshotBytes":1073741824,"cursorTtlMs":900000,"ordering":"ttid-binary-ascending","scope":"persistent-process","restartPolicy":"restart-from-first-page","mutationPolicy":"snapshot-at-first-page"},"wholeRootBackup":{"version":1,"available":true,"configured":false,"machineOperations":["backupStatus","backupReconcile"],"offlineOperations":["backup verify","backup restore"],"metadataFormat":"fylo.posix.v2"}}}`

	identity, err := decodeRuntimeIdentity([]byte(handshake))
	if err != nil {
		t.Fatalf("decodeRuntimeIdentity() error = %v", err)
	}
	if identity.RuntimeVersion != PhaseOneRuntimeVersion {
		t.Fatalf("runtime version = %q, want the pinned %q", identity.RuntimeVersion, PhaseOneRuntimeVersion)
	}
	if identity.BuildKind != "release" || identity.Commit != "39f57b5cf3120c9b9b3b4ead9e749b47b76ac4f0" {
		t.Fatalf("identity = %#v", identity)
	}
	if !identity.Capabilities.Handshake || !identity.Capabilities.ExclusiveRoot {
		t.Fatalf("capabilities = %#v", identity.Capabilities)
	}
}

func testConfig(t *testing.T, mode string) Config {
	t.Helper()

	root := filepath.Join(t.TempDir(), mode)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir(%s): %v", root, err)
	}
	return Config{
		Binary:                 fakeFYLOBinary,
		Root:                   root,
		ExpectedProtocol:       ProtocolVersion,
		ExpectedRuntimeVersion: PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    localRuntimeTarget(),
		MaxRequestBytes:        1024,
		MaxResponseBytes:       4096,
		MaxDiagnosticBytes:     1024,
		ShutdownTimeout:        250 * time.Millisecond,
	}
}
