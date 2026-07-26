package qualification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	sesame "github.com/d31ma/sesame/clients/go/sesame"
	fyloproving "github.com/d31ma/sesame/internal/proving/fylo"
)

const reportSchemaVersion = 1

type scenario struct {
	TenantID          string
	AllowedPrincipal  string
	RevokedPrincipal  string
	AllowedIdentifier sesame.PrincipalIdentifier
	RevokedIdentifier sesame.PrincipalIdentifier
	Request           sesame.DecisionRequest
}

// Run creates private temporary deployments, runs the configured evidence
// stages, and removes only the temporary tree it created.
func Run(ctx context.Context, config Config) (report Report, runErr error) {
	if err := ValidateConfig(config); err != nil {
		return Report{}, err
	}

	report = newReport(config)
	defer func() {
		report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if runErr != nil {
			report.Failure = boundedDiagnostic(runErr.Error())
		}
	}()

	current, err := inspectArtifact(config.SESAMEBinary)
	if err != nil {
		return report, err
	}
	report.CurrentSESAME = current
	fylo, err := inspectFYLOArtifact(ctx, config.FYLOBinary)
	if err != nil {
		return report, err
	}
	report.FYLO = fylo
	if config.PreviousSESAMEBinary != "" {
		previous, previousErr := inspectArtifact(config.PreviousSESAMEBinary)
		if previousErr != nil {
			return report, previousErr
		}
		report.PreviousSESAME = &previous
		if config.Profile == ProfileRelease && previous.SHA256 == current.SHA256 {
			return report, errors.New("release profile requires distinct previous and current SESAME artifacts")
		}
	}

	workspace, err := os.MkdirTemp("", "sesame-production-evidence-*")
	if err != nil {
		return report, fmt.Errorf("create private evidence workspace: %w", err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		_ = os.RemoveAll(workspace)
		return report, fmt.Errorf("restrict evidence workspace: %w", err)
	}
	defer func() {
		runErr = errors.Join(runErr, removeWorkspace(workspace))
	}()

	restoredDeployment, seeded, version, restore, err := runRestore(
		ctx, workspace, config.SESAMEBinary, config.FYLOBinary)
	report.Restore = restore
	report.CurrentSESAME.Version = &version
	if err != nil {
		return report, err
	}

	if config.PreviousSESAMEBinary == "" {
		report.Upgrade = UpgradeEvidence{
			Status: StatusSkipped,
			Reason: "no previous SESAME binary was supplied",
		}
		report.Rollback = RollbackEvidence{
			Status: StatusSkipped,
			Reason: "no previous SESAME binary was supplied",
		}
	} else {
		previousVersion, upgrade, rollback, upgradeErr := runUpgradeRollback(
			ctx,
			workspace,
			config.PreviousSESAMEBinary,
			config.SESAMEBinary,
			config.FYLOBinary,
		)
		report.PreviousSESAME.Version = &previousVersion
		report.Upgrade = upgrade
		report.Rollback = rollback
		if upgradeErr != nil {
			return report, upgradeErr
		}
	}

	if config.Profile == ProfileRelease {
		if err := validateReleaseIdentities(
			report.CurrentSESAME,
			*report.PreviousSESAME,
			report.FYLO,
		); err != nil {
			return report, err
		}
	}

	soak, err := runSoak(ctx, config, restoredDeployment, seeded)
	report.Soak = soak
	if err != nil {
		return report, err
	}

	report.QualificationEligible =
		config.Profile == ProfileRelease &&
			report.Restore.Status == StatusPassed &&
			report.Upgrade.Status == StatusPassed &&
			report.Rollback.Status == StatusPassed &&
			report.Soak.Status == StatusPassed
	return report, nil
}

func newReport(config Config) Report {
	label := config.EnvironmentLabel
	if label == "" {
		label = "unspecified"
	}
	limitations := []string{
		"one run applies only to the exact artifacts, native platform, filesystem, and environment recorded in this report",
		"the restore drill is a cold copy of a stopped complete deployment; provisioned remote-backup recovery remains separate evidence",
		"the compatibility fixture covers tenant, principal, role, grant, and revocation state; every supported stored event type still needs fixture coverage",
		"qualification evidence does not replace an independent security assessment",
	}
	if config.Profile == ProfileSmoke {
		limitations = append(limitations,
			"a smoke profile is never production-support or 72-hour soak evidence")
	}
	if config.PreviousSESAMEBinary == "" {
		limitations = append(limitations,
			"upgrade and rollback are skipped without an explicit previous SESAME binary")
	}

	return Report{
		SchemaVersion: reportSchemaVersion,
		Profile:       config.Profile,
		StartedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Platform: Platform{
			OS:               runtime.GOOS,
			Architecture:     runtime.GOARCH,
			LogicalCPUCount:  runtime.NumCPU(),
			EnvironmentLabel: label,
		},
		Limits: LimitsReport{
			EnforceResources:       config.Limits.EnforceResources,
			MaxP99Milliseconds:     milliseconds(config.Limits.MaxP99),
			MaxHeapGrowthBytes:     config.Limits.MaxHeapGrowthBytes,
			MaxGoroutineGrowth:     config.Limits.MaxGoroutineGrowth,
			MaxDeploymentGrowth:    config.Limits.MaxDeploymentGrowth,
			MaxOperationErrorRatio: config.Limits.MaxOperationErrorRatio,
			MinOperations:          config.MinOperations,
		},
		Limitations: limitations,
	}
}

func inspectArtifact(path string) (Artifact, error) {
	file, err := os.Open(path)
	if err != nil {
		return Artifact{}, fmt.Errorf("open artifact %s: %w", path, err)
	}
	defer file.Close()

	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return Artifact{}, fmt.Errorf("digest artifact %s: %w", path, err)
	}
	return Artifact{
		Path:      path,
		SHA256:    hex.EncodeToString(digest.Sum(nil)),
		SizeBytes: size,
	}, nil
}

func inspectFYLOArtifact(ctx context.Context, path string) (Artifact, error) {
	artifact, err := inspectArtifact(path)
	if err != nil {
		return Artifact{}, err
	}
	command := exec.CommandContext(ctx, path, "version", "--output", "json")
	output, err := command.Output()
	if err != nil {
		// Smoke tests can use a deterministic stand-in that implements only
		// the machine protocol. Release validation below requires this field.
		return artifact, nil
	}
	var identity FYLOIdentity
	if err := json.Unmarshal(output, &identity); err != nil ||
		identity.RuntimeVersion == "" || identity.Commit == "" {
		return artifact, nil
	}
	artifact.FYLO = &identity
	return artifact, nil
}

func validateReleaseIdentities(current, previous, fylo Artifact) error {
	for label, artifact := range map[string]Artifact{
		"current SESAME":  current,
		"previous SESAME": previous,
	} {
		if artifact.Version == nil ||
			artifact.Version.Version == "" ||
			artifact.Version.Version == "dev" ||
			artifact.Version.Commit == "" ||
			artifact.Version.Commit == "unknown" ||
			artifact.Version.BuiltAt == "" ||
			artifact.Version.BuiltAt == "unknown" {
			return fmt.Errorf("%s artifact lacks immutable release metadata", label)
		}
		if artifact.Version.OS != runtime.GOOS || artifact.Version.Arch != runtime.GOARCH {
			return fmt.Errorf(
				"%s artifact targets %s/%s, evidence runner is native %s/%s",
				label,
				artifact.Version.OS,
				artifact.Version.Arch,
				runtime.GOOS,
				runtime.GOARCH,
			)
		}
	}
	if current.Version.Version == previous.Version.Version {
		return fmt.Errorf(
			"previous and current SESAME artifacts both report version %q",
			current.Version.Version,
		)
	}
	if fylo.FYLO == nil ||
		fylo.FYLO.BuildKind != "release" ||
		fylo.FYLO.Commit == "" ||
		fylo.FYLO.Commit == "unknown" {
		return errors.New("FYLO artifact lacks immutable release identity")
	}
	if expected := nativeFYLOTarget(); fylo.FYLO.BuildTarget != expected {
		return fmt.Errorf(
			"FYLO artifact targets %q, evidence runner requires native %q",
			fylo.FYLO.BuildTarget,
			expected,
		)
	}
	return nil
}

func nativeFYLOTarget() string {
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "macos"
	}
	architecture := runtime.GOARCH
	if architecture == "amd64" {
		architecture = "x64"
	}
	return osName + "-" + architecture
}

func runRestore(
	ctx context.Context,
	workspace string,
	sesameBinary string,
	fyloBinary string,
) (string, scenario, sesame.Info, RestoreEvidence, error) {
	started := time.Now()
	evidence := RestoreEvidence{Status: StatusFailed}
	source := filepath.Join(workspace, "restore-source")
	if err := initializeDeployment(ctx, sesameBinary, fyloBinary, source); err != nil {
		return "", scenario{}, sesame.Info{}, evidence, err
	}

	client, err := start(ctx, sesameBinary, source)
	if err != nil {
		return "", scenario{}, sesame.Info{}, evidence, fmt.Errorf("start restore source: %w", err)
	}
	seeded, version, seedErr := seedScenario(ctx, client)
	closeErr := client.Close()
	if err := errors.Join(seedErr, closeErr); err != nil {
		return "", scenario{}, version, evidence, fmt.Errorf("seed restore source: %w", err)
	}

	restored := filepath.Join(workspace, "restore-destination")
	if err := os.Mkdir(restored, 0o700); err != nil {
		return "", scenario{}, version, evidence, fmt.Errorf("create restore destination: %w", err)
	}
	if err := fyloproving.CopyTree(source, restored); err != nil {
		return "", scenario{}, version, evidence, fmt.Errorf("cold-copy stopped deployment: %w", err)
	}

	restoredClient, err := start(ctx, sesameBinary, restored)
	if err != nil {
		return "", scenario{}, version, evidence, fmt.Errorf("start restored deployment: %w", err)
	}
	allowed, revoked, verifyErr := verifyScenario(ctx, restoredClient, seeded)
	closeErr = restoredClient.Close()
	if err := errors.Join(verifyErr, closeErr); err != nil {
		return "", scenario{}, version, evidence, fmt.Errorf("verify restored deployment: %w", err)
	}

	evidence.Status = StatusPassed
	evidence.DurationMilliseconds = milliseconds(time.Since(started))
	evidence.AllowedDecision = allowed.Decision
	evidence.AllowedReason = allowed.ReasonCode
	evidence.RevokedDecision = revoked.Decision
	evidence.RevokedReason = revoked.ReasonCode
	return restored, seeded, version, evidence, nil
}

func runUpgradeRollback(
	ctx context.Context,
	workspace string,
	previousBinary string,
	currentBinary string,
	fyloBinary string,
) (sesame.Info, UpgradeEvidence, RollbackEvidence, error) {
	upgrade := UpgradeEvidence{Status: StatusFailed}
	rollback := RollbackEvidence{Status: StatusSkipped, Reason: "upgrade did not complete"}
	deployment := filepath.Join(workspace, "upgrade-fixture")
	if err := initializeDeployment(ctx, previousBinary, fyloBinary, deployment); err != nil {
		return sesame.Info{}, upgrade, rollback, fmt.Errorf("initialize previous-version fixture: %w", err)
	}

	previous, err := start(ctx, previousBinary, deployment)
	if err != nil {
		return sesame.Info{}, upgrade, rollback, fmt.Errorf("start previous SESAME binary: %w", err)
	}
	seeded, previousVersion, seedErr := seedScenario(ctx, previous)
	closeErr := previous.Close()
	if err := errors.Join(seedErr, closeErr); err != nil {
		return previousVersion, upgrade, rollback, fmt.Errorf("seed previous-version fixture: %w", err)
	}

	upgradeStarted := time.Now()
	current, err := start(ctx, currentBinary, deployment)
	if err != nil {
		return previousVersion, upgrade, rollback, fmt.Errorf("upgrade fixture with current binary: %w", err)
	}
	_, _, baselineErr := verifyScenario(ctx, current, seeded)
	upgrade.BaselinePreserved = baselineErr == nil
	marker := sesame.PrincipalIdentifier{
		Namespace: "email",
		Value:     "current-write@qualification.invalid",
	}
	markerPrincipal, markerErr := current.PrincipalCreate(
		ctx, seeded.TenantID, "workload", marker)
	upgrade.CurrentWriteStored = markerErr == nil && markerPrincipal.ID != ""
	closeErr = current.Close()
	if err := errors.Join(baselineErr, markerErr, closeErr); err != nil {
		upgrade.DurationMilliseconds = milliseconds(time.Since(upgradeStarted))
		return previousVersion, upgrade, rollback, fmt.Errorf("exercise upgraded fixture: %w", err)
	}
	upgrade.Status = StatusPassed
	upgrade.DurationMilliseconds = milliseconds(time.Since(upgradeStarted))

	rollbackStarted := time.Now()
	rollback.Status = StatusFailed
	rollback.Reason = ""
	rolledBack, err := start(ctx, previousBinary, deployment)
	if err != nil {
		rollback.DurationMilliseconds = milliseconds(time.Since(rollbackStarted))
		return previousVersion, upgrade, rollback, fmt.Errorf("rollback fixture with previous binary: %w", err)
	}
	_, _, baselineErr = verifyScenario(ctx, rolledBack, seeded)
	rollback.BaselinePreserved = baselineErr == nil
	visible, markerReadErr := rolledBack.PrincipalGetByIdentifier(ctx, seeded.TenantID, marker)
	rollback.CurrentWriteVisible = markerReadErr == nil && visible.ID == markerPrincipal.ID
	closeErr = rolledBack.Close()
	if err := errors.Join(baselineErr, markerReadErr, closeErr); err != nil {
		rollback.DurationMilliseconds = milliseconds(time.Since(rollbackStarted))
		return previousVersion, upgrade, rollback, fmt.Errorf("verify rollback fixture: %w", err)
	}
	rollback.Status = StatusPassed
	rollback.DurationMilliseconds = milliseconds(time.Since(rollbackStarted))
	return previousVersion, upgrade, rollback, nil
}

func initializeDeployment(ctx context.Context, sesameBinary, fyloBinary, destination string) error {
	command := exec.CommandContext(ctx, sesameBinary,
		"init",
		"--deployment", destination,
		"--fylo-binary", fyloBinary,
	)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("sesame init: %w: %s", err, boundedDiagnostic(stderr.String()))
	}
	var summary struct {
		Deployment string `json:"deployment"`
		FYLOBinary string `json:"fylo_binary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		return fmt.Errorf("decode sesame init output: %w", err)
	}
	if summary.Deployment != destination || summary.FYLOBinary != fyloBinary {
		return fmt.Errorf("sesame init described unexpected deployment %q and FYLO binary %q",
			summary.Deployment, summary.FYLOBinary)
	}
	return nil
}

func start(ctx context.Context, binary, deployment string) (*sesame.Client, error) {
	return sesame.Start(ctx, sesame.Options{
		Binary:     binary,
		Deployment: deployment,
	})
}

func seedScenario(ctx context.Context, client *sesame.Client) (scenario, sesame.Info, error) {
	version, err := client.Version(ctx)
	if err != nil {
		return scenario{}, sesame.Info{}, err
	}
	admin, err := client.AdminBootstrap(ctx, "qualification", sesame.PrincipalIdentifier{
		Namespace: "email",
		Value:     "administrator@qualification.invalid",
	})
	if err != nil {
		return scenario{}, version, err
	}
	role, err := client.RoleCreate(ctx, admin.Tenant.ID, "document-reader", []sesame.Permission{{
		Action:   "document.read",
		Resource: "document:qualification",
	}})
	if err != nil {
		return scenario{}, version, err
	}

	allowedIdentifier := sesame.PrincipalIdentifier{
		Namespace: "email",
		Value:     "allowed@qualification.invalid",
	}
	allowed, err := client.PrincipalCreate(ctx, admin.Tenant.ID, "human", allowedIdentifier)
	if err != nil {
		return scenario{}, version, err
	}
	if _, err := client.GrantCreate(ctx, admin.Tenant.ID, allowed.ID, role.ID); err != nil {
		return scenario{}, version, err
	}

	revokedIdentifier := sesame.PrincipalIdentifier{
		Namespace: "email",
		Value:     "revoked@qualification.invalid",
	}
	revoked, err := client.PrincipalCreate(ctx, admin.Tenant.ID, "human", revokedIdentifier)
	if err != nil {
		return scenario{}, version, err
	}
	revokedGrant, err := client.GrantCreate(ctx, admin.Tenant.ID, revoked.ID, role.ID)
	if err != nil {
		return scenario{}, version, err
	}
	if err := client.GrantRevoke(ctx, revokedGrant.ID); err != nil {
		return scenario{}, version, err
	}

	seeded := scenario{
		TenantID:          admin.Tenant.ID,
		AllowedPrincipal:  allowed.ID,
		RevokedPrincipal:  revoked.ID,
		AllowedIdentifier: allowedIdentifier,
		RevokedIdentifier: revokedIdentifier,
		Request: sesame.DecisionRequest{
			TenantID: admin.Tenant.ID,
			Action:   "document.read",
			Resource: "document:qualification",
		},
	}
	allowedDecision, revokedDecision, err := verifyScenario(ctx, client, seeded)
	if err != nil {
		return scenario{}, version, err
	}
	if allowedDecision.Decision != "allow" || revokedDecision.Decision != "deny" {
		return scenario{}, version, fmt.Errorf(
			"seed decisions were %q and %q, want allow and deny",
			allowedDecision.Decision, revokedDecision.Decision)
	}
	return seeded, version, nil
}

func verifyScenario(
	ctx context.Context,
	client *sesame.Client,
	seeded scenario,
) (sesame.Decision, sesame.Decision, error) {
	allowedPrincipal, err := client.PrincipalGetByIdentifier(
		ctx, seeded.TenantID, seeded.AllowedIdentifier)
	if err != nil {
		return sesame.Decision{}, sesame.Decision{}, err
	}
	if allowedPrincipal.ID != seeded.AllowedPrincipal {
		return sesame.Decision{}, sesame.Decision{},
			fmt.Errorf("allowed principal changed from %s to %s",
				seeded.AllowedPrincipal, allowedPrincipal.ID)
	}
	allowedRequest := seeded.Request
	allowedRequest.PrincipalID = allowedPrincipal.ID
	allowed, err := client.Decide(ctx, allowedRequest, nil)
	if err != nil {
		return sesame.Decision{}, sesame.Decision{}, err
	}

	revokedPrincipal, err := client.PrincipalGetByIdentifier(
		ctx, seeded.TenantID, seeded.RevokedIdentifier)
	if err != nil {
		return sesame.Decision{}, sesame.Decision{}, err
	}
	if revokedPrincipal.ID != seeded.RevokedPrincipal {
		return sesame.Decision{}, sesame.Decision{},
			fmt.Errorf("revoked principal changed from %s to %s",
				seeded.RevokedPrincipal, revokedPrincipal.ID)
	}
	revokedRequest := seeded.Request
	revokedRequest.PrincipalID = revokedPrincipal.ID
	revoked, err := client.Decide(ctx, revokedRequest, nil)
	if err != nil {
		return sesame.Decision{}, sesame.Decision{}, err
	}
	if allowed.Decision != "allow" || revoked.Decision != "deny" {
		return sesame.Decision{}, sesame.Decision{},
			fmt.Errorf("replayed decisions were %q and %q, want allow and deny",
				allowed.Decision, revoked.Decision)
	}
	return allowed, revoked, nil
}

func boundedDiagnostic(value string) string {
	const maximum = 4096
	if len(value) <= maximum {
		return value
	}
	return value[len(value)-maximum:]
}

func removeWorkspace(path string) error {
	temporary := filepath.Clean(os.TempDir()) + string(os.PathSeparator)
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) ||
		!bytes.HasPrefix([]byte(cleaned+string(os.PathSeparator)), []byte(temporary)) {
		return fmt.Errorf("refuse to remove non-temporary evidence workspace %q", path)
	}
	if err := os.RemoveAll(cleaned); err != nil {
		return fmt.Errorf("remove evidence workspace: %w", err)
	}
	return nil
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
