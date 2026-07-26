package qualification

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	sesame "github.com/d31ma/sesame/clients/go/sesame"
)

var (
	testBinariesRoot string
	testSESAMEBinary string
	testFYLOBinary   string
)

func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "sesame-qualification-test-*")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create qualification test directory: %v\n", err)
		os.Exit(1)
	}
	testBinariesRoot = root

	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	testSESAMEBinary = filepath.Join(root, "sesame"+suffix)
	testFYLOBinary = filepath.Join(root, "fylo"+suffix)

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		_, _ = fmt.Fprintln(os.Stderr, "locate qualification test source")
		os.Exit(1)
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	for target, source := range map[string]string{
		testSESAMEBinary: "./cmd/sesame",
		testFYLOBinary:   "./internal/adapters/fylo/testdata/fakefylo",
	} {
		command := exec.Command("go", "build", "-trimpath", "-o", target, source)
		command.Dir = repositoryRoot
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
		if output, buildErr := command.CombinedOutput(); buildErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "build %s: %v\n%s", source, buildErr, output)
			os.Exit(1)
		}
	}

	exitCode := m.Run()
	_ = os.RemoveAll(root)
	os.Exit(exitCode)
}

func TestReleaseProfileRequiresCompleteQualificationInputs(t *testing.T) {
	base := Config{
		Profile:          ProfileRelease,
		SESAMEBinary:     testSESAMEBinary,
		FYLOBinary:       testFYLOBinary,
		EnvironmentLabel: "qualification-test-runner",
		SoakDuration:     72 * time.Hour,
		MinOperations:    1,
		Limits: Limits{
			EnforceResources:       true,
			MaxP99:                 time.Second,
			MaxHeapGrowthBytes:     1 << 30,
			MaxGoroutineGrowth:     10,
			MaxDeploymentGrowth:    1 << 30,
			MaxOperationErrorRatio: 0,
		},
	}

	if err := ValidateConfig(base); err == nil {
		t.Fatal("release profile accepted no previous SESAME binary")
	}

	base.PreviousSESAMEBinary = testSESAMEBinary
	base.SoakDuration = 71*time.Hour + 59*time.Minute
	if err := ValidateConfig(base); err == nil {
		t.Fatal("release profile accepted a soak shorter than 72 hours")
	}

	base.SoakDuration = 72 * time.Hour
	base.Limits.EnforceResources = false
	if err := ValidateConfig(base); err == nil {
		t.Fatal("release profile accepted observational resource metrics")
	}

	base.Limits.EnforceResources = true
	if err := ValidateConfig(base); err != nil {
		t.Fatalf("complete release profile rejected: %v", err)
	}
}

func TestConfigRejectsUnboundedOrAmbiguousInputs(t *testing.T) {
	valid := Config{
		Profile:       ProfileSmoke,
		SESAMEBinary:  testSESAMEBinary,
		FYLOBinary:    testFYLOBinary,
		SoakDuration:  time.Second,
		MinOperations: 1,
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"profile", func(config *Config) { config.Profile = "other" }, "profile must be"},
		{"relative artifact", func(config *Config) { config.SESAMEBinary = "sesame" }, "must be absolute"},
		{"duration", func(config *Config) { config.SoakDuration = 0 }, "duration must be positive"},
		{"operations", func(config *Config) { config.MinOperations = 0 }, "operations must be positive"},
		{"negative error ratio", func(config *Config) {
			config.Limits.MaxOperationErrorRatio = -0.1
		}, "error ratio"},
		{"large error ratio", func(config *Config) {
			config.Limits.MaxOperationErrorRatio = 1.1
		}, "error ratio"},
		{"negative resource", func(config *Config) {
			config.Limits.MaxHeapGrowthBytes = -1
		}, "cannot be negative"},
		{"missing p99", func(config *Config) {
			config.Limits.EnforceResources = true
		}, "positive p99"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			err := ValidateConfig(config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateConfig() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestReleaseIdentityRejectsDevelopmentArtifacts(t *testing.T) {
	releaseInfo := &sesame.Info{
		Version: "1.0.0",
		Commit:  "0123456789abcdef",
		BuiltAt: "2026-07-26T00:00:00Z",
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
	previousInfo := *releaseInfo
	previousInfo.Version = "0.9.0"
	fylo := Artifact{FYLO: &FYLOIdentity{
		RuntimeVersion: "26.30.06",
		Commit:         "fedcba9876543210",
		BuildKind:      "release",
		BuildTarget:    nativeFYLOTarget(),
	}}
	if err := validateReleaseIdentities(
		Artifact{Version: releaseInfo},
		Artifact{Version: &previousInfo},
		fylo,
	); err != nil {
		t.Fatalf("release identities rejected: %v", err)
	}

	development := *releaseInfo
	development.Version = "dev"
	development.Commit = "unknown"
	if err := validateReleaseIdentities(
		Artifact{Version: &development},
		Artifact{Version: &previousInfo},
		fylo,
	); err == nil {
		t.Fatal("development SESAME artifact was accepted as release evidence")
	}
	if err := validateReleaseIdentities(
		Artifact{Version: releaseInfo},
		Artifact{Version: &previousInfo},
		Artifact{},
	); err == nil {
		t.Fatal("FYLO artifact without immutable runtime identity was accepted")
	}
}

func TestSmokeProfileProvesColdRestoreAndBoundedSoak(t *testing.T) {
	report, err := Run(context.Background(), Config{
		Profile:       ProfileSmoke,
		SESAMEBinary:  testSESAMEBinary,
		FYLOBinary:    testFYLOBinary,
		SoakDuration:  75 * time.Millisecond,
		MinOperations: 12,
		Limits: Limits{
			EnforceResources:       true,
			MaxP99:                 5 * time.Second,
			MaxHeapGrowthBytes:     1 << 30,
			MaxGoroutineGrowth:     100,
			MaxDeploymentGrowth:    1 << 30,
			MaxOperationErrorRatio: 0,
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v\nreport = %#v", err, report)
	}

	if report.QualificationEligible {
		t.Fatal("a smoke run was marked qualification eligible")
	}
	if report.Restore.Status != StatusPassed {
		t.Fatalf("restore status = %q", report.Restore.Status)
	}
	if report.Restore.AllowedDecision != "allow" || report.Restore.RevokedDecision != "deny" {
		t.Fatalf("restored decisions = %#v", report.Restore)
	}
	if report.Upgrade.Status != StatusSkipped || report.Rollback.Status != StatusSkipped {
		t.Fatalf("upgrade/rollback without a previous binary = %#v / %#v",
			report.Upgrade, report.Rollback)
	}
	if report.Soak.Status != StatusPassed || report.Soak.Operations < 12 {
		t.Fatalf("soak result = %#v", report.Soak)
	}
	if report.Soak.WriteOperations == 0 || report.Soak.DeploymentBytesAfter <= report.Soak.DeploymentBytesBefore {
		t.Fatalf("soak did not exercise or measure durable growth: %#v", report.Soak)
	}
	if len(report.Limitations) == 0 {
		t.Fatal("report omitted support-claim limitations")
	}
}

func TestUpgradeAndRollbackFixtureUsesBothBinaries(t *testing.T) {
	report, err := Run(context.Background(), Config{
		Profile:              ProfileSmoke,
		SESAMEBinary:         testSESAMEBinary,
		PreviousSESAMEBinary: testSESAMEBinary,
		FYLOBinary:           testFYLOBinary,
		SoakDuration:         25 * time.Millisecond,
		MinOperations:        2,
		Limits: Limits{
			MaxOperationErrorRatio: 0,
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v\nreport = %#v", err, report)
	}
	if report.Upgrade.Status != StatusPassed {
		t.Fatalf("upgrade = %#v", report.Upgrade)
	}
	if report.Rollback.Status != StatusPassed || !report.Rollback.CurrentWriteVisible {
		t.Fatalf("rollback = %#v", report.Rollback)
	}
	if report.CurrentSESAME.SHA256 == "" || report.PreviousSESAME == nil ||
		report.PreviousSESAME.SHA256 == "" ||
		report.FYLO.SHA256 == "" {
		t.Fatalf("artifact identity is incomplete: %#v", report)
	}
}

func TestLatencyHistogramIsBoundedAndReportsAnUpperBound(t *testing.T) {
	var histogram latencyHistogram
	for index := 1; index <= 100_000; index++ {
		histogram.Observe(time.Duration(index) * time.Microsecond)
	}
	if histogram.total != 100_000 {
		t.Fatalf("histogram count = %d", histogram.total)
	}
	if got := histogram.Percentile(0.50); got < 50*time.Millisecond ||
		got > 52*time.Millisecond {
		t.Fatalf("p50 upper bound = %s", got)
	}
	if got := histogram.Percentile(0.99); got < 99*time.Millisecond ||
		got > 103*time.Millisecond {
		t.Fatalf("p99 upper bound = %s", got)
	}
	if len(histogram.buckets) != latencyHistogramBuckets {
		t.Fatalf("histogram grew to %d buckets", len(histogram.buckets))
	}
}

func TestEveryResourceLimitProducesAStableViolation(t *testing.T) {
	violations := resourceLimitViolations(SoakEvidence{
		P99Milliseconds:       20,
		HeapGrowthBytes:       200,
		GoroutineGrowth:       2,
		DeploymentGrowthBytes: 300,
	}, Limits{
		MaxP99:              10 * time.Millisecond,
		MaxHeapGrowthBytes:  100,
		MaxGoroutineGrowth:  1,
		MaxDeploymentGrowth: 200,
	})
	if len(violations) != 4 {
		t.Fatalf("resource violations = %v", violations)
	}
	for _, fragment := range []string{"p99", "heap growth", "goroutine growth", "deployment growth"} {
		found := false
		for _, violation := range violations {
			found = found || strings.Contains(violation.Error(), fragment)
		}
		if !found {
			t.Errorf("no violation contains %q: %v", fragment, violations)
		}
	}
}
