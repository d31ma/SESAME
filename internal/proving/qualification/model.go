// Package qualification runs destructive production-evidence drills only
// against private temporary deployments that it creates itself.
package qualification

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	sesame "github.com/d31ma/sesame/clients/go/sesame"
)

// Profile controls whether a run is observational smoke evidence or eligible
// for the full release gate.
type Profile string

const (
	// ProfileSmoke permits short local runs but can never qualify a release.
	ProfileSmoke Profile = "smoke"
	// ProfileRelease enforces the minimum production-support evidence inputs.
	ProfileRelease Profile = "release"

	// StatusPassed means the stage completed and met every configured limit.
	StatusPassed = "passed"
	// StatusFailed means the stage ran but did not preserve its invariant.
	StatusFailed = "failed"
	// StatusSkipped means the stage lacked an explicitly optional input.
	StatusSkipped = "skipped"

	releaseSoakMinimum = 72 * time.Hour
)

// Limits are the declared pass/fail thresholds for one qualification run.
// Error ratio and minimum operations are always enforced. Resource thresholds
// are observational unless EnforceResources is true.
type Limits struct {
	EnforceResources       bool          `json:"enforce_resources"`
	MaxP99                 time.Duration `json:"-"`
	MaxHeapGrowthBytes     int64         `json:"max_heap_growth_bytes"`
	MaxGoroutineGrowth     int           `json:"max_goroutine_growth"`
	MaxDeploymentGrowth    int64         `json:"max_deployment_growth_bytes"`
	MaxOperationErrorRatio float64       `json:"max_operation_error_ratio"`
}

// Config selects exact artifacts and the workload used by Run.
type Config struct {
	Profile              Profile
	SESAMEBinary         string
	PreviousSESAMEBinary string
	FYLOBinary           string
	EnvironmentLabel     string
	SoakDuration         time.Duration
	MinOperations        int
	Limits               Limits
}

// Artifact identifies one exact executable used by a run.
type Artifact struct {
	Path      string        `json:"path"`
	SHA256    string        `json:"sha256"`
	SizeBytes int64         `json:"size_bytes"`
	Version   *sesame.Info  `json:"version,omitempty"`
	FYLO      *FYLOIdentity `json:"fylo_identity,omitempty"`
}

// FYLOIdentity is the signed runtime identity printed by `fylo version`.
type FYLOIdentity struct {
	RuntimeVersion  string `json:"runtimeVersion"`
	ProtocolVersion int    `json:"protocolVersion"`
	Commit          string `json:"commit"`
	BuildTarget     string `json:"buildTarget"`
	BuildKind       string `json:"buildKind"`
}

// Platform records the native process target without collecting host identity.
type Platform struct {
	OS               string `json:"os"`
	Architecture     string `json:"architecture"`
	LogicalCPUCount  int    `json:"logical_cpu_count"`
	EnvironmentLabel string `json:"environment_label"`
}

// LimitsReport is the JSON-safe representation of configured limits.
type LimitsReport struct {
	EnforceResources       bool    `json:"enforce_resources"`
	MaxP99Milliseconds     float64 `json:"max_p99_milliseconds,omitempty"`
	MaxHeapGrowthBytes     int64   `json:"max_heap_growth_bytes"`
	MaxGoroutineGrowth     int     `json:"max_goroutine_growth"`
	MaxDeploymentGrowth    int64   `json:"max_deployment_growth_bytes"`
	MaxOperationErrorRatio float64 `json:"max_operation_error_ratio"`
	MinOperations          int     `json:"min_operations"`
}

// RestoreEvidence proves both an applicable allow and a durable revoked deny
// after copying a stopped deployment into a distinct root.
type RestoreEvidence struct {
	Status               string  `json:"status"`
	DurationMilliseconds float64 `json:"duration_milliseconds"`
	AllowedDecision      string  `json:"allowed_decision,omitempty"`
	AllowedReason        string  `json:"allowed_reason,omitempty"`
	RevokedDecision      string  `json:"revoked_decision,omitempty"`
	RevokedReason        string  `json:"revoked_reason,omitempty"`
}

// UpgradeEvidence proves the current binary can replay and extend state
// created by the explicitly supplied previous binary.
type UpgradeEvidence struct {
	Status               string  `json:"status"`
	DurationMilliseconds float64 `json:"duration_milliseconds,omitempty"`
	Reason               string  `json:"reason,omitempty"`
	BaselinePreserved    bool    `json:"baseline_preserved"`
	CurrentWriteStored   bool    `json:"current_write_stored"`
}

// RollbackEvidence proves the previous binary can replay both its baseline
// state and the compatibility marker written by the current binary.
type RollbackEvidence struct {
	Status               string  `json:"status"`
	DurationMilliseconds float64 `json:"duration_milliseconds,omitempty"`
	Reason               string  `json:"reason,omitempty"`
	BaselinePreserved    bool    `json:"baseline_preserved"`
	CurrentWriteVisible  bool    `json:"current_write_visible"`
}

// SoakEvidence reports observed latency and resource growth for the exact
// workload and artifacts named in Report.
type SoakEvidence struct {
	Status                    string  `json:"status"`
	DurationMilliseconds      float64 `json:"duration_milliseconds"`
	Operations                int     `json:"operations"`
	WriteOperations           int     `json:"write_operations"`
	OperationErrors           int     `json:"operation_errors"`
	OperationErrorRatio       float64 `json:"operation_error_ratio"`
	OperationsPerSecond       float64 `json:"operations_per_second"`
	LatencyHistogram          string  `json:"latency_histogram"`
	P50Milliseconds           float64 `json:"p50_milliseconds"`
	P95Milliseconds           float64 `json:"p95_milliseconds"`
	P99Milliseconds           float64 `json:"p99_milliseconds"`
	HeapBytesBefore           uint64  `json:"heap_bytes_before"`
	HeapBytesAfter            uint64  `json:"heap_bytes_after"`
	HeapGrowthBytes           int64   `json:"heap_growth_bytes"`
	GoroutinesBefore          int     `json:"goroutines_before"`
	GoroutinesAfter           int     `json:"goroutines_after"`
	GoroutineGrowth           int     `json:"goroutine_growth"`
	DeploymentBytesBefore     int64   `json:"deployment_bytes_before"`
	DeploymentBytesAfter      int64   `json:"deployment_bytes_after"`
	DeploymentGrowthBytes     int64   `json:"deployment_growth_bytes"`
	ConfiguredDurationSeconds float64 `json:"configured_duration_seconds"`
}

// Report is one machine-readable production-evidence attempt.
type Report struct {
	SchemaVersion         int              `json:"schema_version"`
	Profile               Profile          `json:"profile"`
	StartedAt             string           `json:"started_at"`
	CompletedAt           string           `json:"completed_at,omitempty"`
	QualificationEligible bool             `json:"qualification_eligible"`
	Platform              Platform         `json:"platform"`
	CurrentSESAME         Artifact         `json:"current_sesame"`
	PreviousSESAME        *Artifact        `json:"previous_sesame,omitempty"`
	FYLO                  Artifact         `json:"fylo"`
	Limits                LimitsReport     `json:"limits"`
	Restore               RestoreEvidence  `json:"restore"`
	Upgrade               UpgradeEvidence  `json:"upgrade"`
	Rollback              RollbackEvidence `json:"rollback"`
	Soak                  SoakEvidence     `json:"soak"`
	Limitations           []string         `json:"limitations"`
	Failure               string           `json:"failure,omitempty"`
}

// ValidateConfig refuses ambiguous artifacts and prevents a short smoke run
// from being labeled release qualification.
func ValidateConfig(config Config) error {
	if config.Profile != ProfileSmoke && config.Profile != ProfileRelease {
		return fmt.Errorf("profile must be %q or %q", ProfileSmoke, ProfileRelease)
	}
	for label, path := range map[string]string{
		"SESAME binary": config.SESAMEBinary,
		"FYLO binary":   config.FYLOBinary,
	} {
		if err := validateArtifactPath(label, path); err != nil {
			return err
		}
	}
	if config.PreviousSESAMEBinary != "" {
		if err := validateArtifactPath("previous SESAME binary", config.PreviousSESAMEBinary); err != nil {
			return err
		}
	}
	if err := validateWorkload(config); err != nil {
		return err
	}
	if config.Profile == ProfileRelease {
		return validateReleaseConfig(config)
	}
	return nil
}

func validateWorkload(config Config) error {
	if config.SoakDuration <= 0 {
		return errors.New("soak duration must be positive")
	}
	if config.MinOperations <= 0 {
		return errors.New("minimum operations must be positive")
	}
	if config.Limits.MaxOperationErrorRatio < 0 || config.Limits.MaxOperationErrorRatio > 1 {
		return errors.New("maximum operation error ratio must be between 0 and 1")
	}
	if config.Limits.MaxP99 < 0 || config.Limits.MaxHeapGrowthBytes < 0 ||
		config.Limits.MaxGoroutineGrowth < 0 || config.Limits.MaxDeploymentGrowth < 0 {
		return errors.New("resource limits cannot be negative")
	}
	if config.Limits.EnforceResources && config.Limits.MaxP99 <= 0 {
		return errors.New("an enforced resource profile requires a positive p99 limit")
	}
	return nil
}

func validateReleaseConfig(config Config) error {
	if config.PreviousSESAMEBinary == "" {
		return errors.New("release profile requires a previous SESAME binary for upgrade and rollback")
	}
	if config.SoakDuration < releaseSoakMinimum {
		return fmt.Errorf("release profile requires at least %s of soak", releaseSoakMinimum)
	}
	if !config.Limits.EnforceResources {
		return errors.New("release profile requires explicit resource limits")
	}
	if config.EnvironmentLabel == "" {
		return errors.New("release profile requires a reference-hardware environment label")
	}
	return nil
}

func validateArtifactPath(label, path string) error {
	if path == "" {
		return fmt.Errorf("%s is required", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s path must be absolute so evidence identifies one exact artifact", label)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s is not a regular file", label, path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s %s is not executable", label, path)
	}
	return nil
}
