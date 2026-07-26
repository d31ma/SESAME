package blackbox_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDeploymentLifecycleNeverLeaksKeyMaterial drives init, doctor, tenant
// commands, and a machine session through compiled binaries, then asserts the
// snapshot key never appears on any stream and diagnostics stay structured.
func TestDeploymentLifecycleNeverLeaksKeyMaterial(t *testing.T) {
	t.Parallel()

	repositoryRoot := findRepositoryRoot(t)
	binDir := t.TempDir()
	sesameBinary := filepath.Join(binDir, "sesame")
	fakeFYLO := filepath.Join(binDir, "fake-fylo")
	if runtime.GOOS == "windows" {
		sesameBinary += ".exe"
		fakeFYLO += ".exe"
	}
	for target, source := range map[string]string{
		sesameBinary: "./cmd/sesame",
		fakeFYLO:     "./internal/adapters/fylo/testdata/fakefylo",
	} {
		build := exec.Command("go", "build", "-trimpath", "-o", target, source)
		build.Dir = repositoryRoot
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go build %s error = %v\n%s", source, err, output)
		}
	}

	deploymentDir := filepath.Join(t.TempDir(), "deployment")
	var transcripts []string
	runCommand := func(stdin string, arguments ...string) (string, string, int) {
		command := exec.Command(sesameBinary, arguments...)
		if stdin != "" {
			command.Stdin = strings.NewReader(stdin)
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		_ = command.Run()
		transcripts = append(transcripts, stdout.String(), stderr.String())
		return stdout.String(), stderr.String(), command.ProcessState.ExitCode()
	}

	initOut, initErr, code := runCommand("", "init", "--deployment", deploymentDir, "--fylo-binary", fakeFYLO)
	if code != 0 {
		t.Fatalf("init exit = %d; stderr = %s", code, initErr)
	}
	var initSummary map[string]any
	if err := json.Unmarshal([]byte(initOut), &initSummary); err != nil {
		t.Fatalf("init output is not JSON: %q: %v", initOut, err)
	}
	if _, exists := initSummary["snapshot_key"]; exists {
		t.Fatal("init summary exposes key material")
	}

	keyBytes, err := os.ReadFile(filepath.Join(deploymentDir, "keys", "snapshot.key"))
	if err != nil {
		t.Fatalf("read snapshot key canary: %v", err)
	}
	canary := strings.TrimSpace(string(keyBytes))
	if len(canary) != 64 {
		t.Fatalf("snapshot key canary length = %d, want 64 hex characters", len(canary))
	}

	doctorOut, doctorErr, code := runCommand("", "doctor", "--deployment", deploymentDir)
	if code != 0 {
		t.Fatalf("doctor exit = %d; stdout = %s stderr = %s", code, doctorOut, doctorErr)
	}

	bootstrapOut, bootstrapErr, code := runCommand("", "tenant", "bootstrap", "--name", "Acme", "--deployment", deploymentDir)
	if code != 0 {
		t.Fatalf("bootstrap exit = %d; stderr = %s", code, bootstrapErr)
	}
	var bootstrap struct {
		Created bool `json:"created"`
		Tenant  struct {
			ID string `json:"tenant_id"`
		} `json:"tenant"`
	}
	if err := json.Unmarshal([]byte(bootstrapOut), &bootstrap); err != nil || !bootstrap.Created {
		t.Fatalf("bootstrap output = %q, %v", bootstrapOut, err)
	}

	doctorOut, doctorErr, code = runCommand("", "doctor", "--deployment", deploymentDir)
	if code != 0 {
		t.Fatalf("post-bootstrap doctor exit = %d; stdout = %s stderr = %s", code, doctorOut, doctorErr)
	}
	var report struct {
		Status string `json:"status"`
		Ledger struct {
			SnapshotUsed         bool `json:"snapshot_used"`
			SnapshotsStored      int  `json:"snapshots_stored"`
			FullReplayEquivalent bool `json:"full_replay_equivalent"`
		} `json:"ledger"`
	}
	if err := json.Unmarshal([]byte(doctorOut), &report); err != nil {
		t.Fatalf("doctor output is not JSON: %q: %v", doctorOut, err)
	}
	if report.Status != "ok" || !report.Ledger.SnapshotUsed ||
		report.Ledger.SnapshotsStored < 1 || !report.Ledger.FullReplayEquivalent {
		t.Fatalf("doctor report = %s", doctorOut)
	}

	machineInput := strings.Join([]string{
		`{"protocol_version":"1","request_id":"ready-1","operation":"system.readiness","parameters":{}}`,
		`{"protocol_version":"1","request_id":"get-1","operation":"tenant.get","parameters":{"name":"acme"}}`,
		`{"protocol_version":"1","request_id":"metrics-1","operation":"system.metrics","parameters":{}}`,
	}, "\n") + "\n"
	machineOut, machineErr, code := runCommand(machineInput, "exec", "--loop", "--deployment", deploymentDir)
	if code != 0 {
		t.Fatalf("exec exit = %d; stderr = %s", code, machineErr)
	}
	lines := strings.Split(strings.TrimSpace(machineOut), "\n")
	if len(lines) != 3 {
		t.Fatalf("machine session produced %d responses: %q", len(lines), machineOut)
	}
	for index, line := range lines {
		var response struct {
			OK     bool `json:"ok"`
			Result json.RawMessage
		}
		if err := json.Unmarshal([]byte(line), &response); err != nil || !response.OK {
			t.Fatalf("machine response %d = %q, %v", index, line, err)
		}
	}
	if !strings.Contains(lines[0], `"status":"ok"`) {
		t.Fatalf("readiness with deployment = %q", lines[0])
	}
	if !strings.Contains(lines[1], bootstrap.Tenant.ID) {
		t.Fatalf("tenant.get did not return the bootstrap tenant: %q", lines[1])
	}
	if !strings.Contains(lines[2], `"storage_configured":true`) {
		t.Fatalf("metrics with deployment = %q", lines[2])
	}
	for _, line := range strings.Split(strings.TrimSpace(machineErr), "\n") {
		var record struct {
			Level string `json:"level"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil || record.Level == "" {
			t.Fatalf("machine stderr line is not a structured log record: %q", line)
		}
	}

	// The canary sweep: no captured stream from any command may contain the
	// snapshot key.
	for index, transcript := range transcripts {
		if strings.Contains(transcript, canary) {
			t.Fatalf("transcript %d leaks the snapshot key", index)
		}
	}
}
