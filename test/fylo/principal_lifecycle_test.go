package fylo_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// TestRealFYLOPrincipalLifecycleSurvivesRestart proves principal creation,
// identifier claiming, and durable suspension against a real FYLO runtime
// across a forced process death.
func TestRealFYLOPrincipalLifecycleSurvivesRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}

	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}

	root, err := os.MkdirTemp("", "sesame-principal-lifecycle-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// A fixed key exercises verified snapshots against the real runtime.
	snapshotKey := make([]byte, 32)
	for index := range snapshotKey {
		snapshotKey[index] = byte(index + 1)
	}

	client, err := fyloadapter.Start(ctx, config)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	ledger, replay, err := securityledger.OpenVerified(ctx, client, snapshotKey)
	if err != nil {
		t.Fatalf("OpenVerified() error = %v", err)
	}
	service, err := identityapp.NewFromSnapshot(ledger, replay.SnapshotState, replay.TailEvents)
	if err != nil {
		t.Fatalf("identity.NewFromSnapshot() error = %v", err)
	}
	service.UseSnapshots(ledger)

	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "Alice@Example.com"}
	created, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman, identifier, "test:integration")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if _, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindWorkload, identifier, "test:integration"); err == nil {
		t.Fatal("duplicate identifier claim succeeded")
	}
	if _, err := service.PrincipalSuspend(ctx, created.ID, "test:integration"); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}

	// Die without a clean shutdown; the acknowledged deny state must replay.
	if err := client.Crash(); err != nil {
		t.Fatalf("Crash() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	restarted, err := fyloadapter.Start(ctx, config)
	if err != nil {
		t.Fatalf("restart Start() error = %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	_, restartReplay, err := securityledger.OpenVerified(ctx, restarted, snapshotKey)
	if err != nil {
		t.Fatalf("restart OpenVerified() error = %v", err)
	}
	// The snapshot written after the suspension bounds replay to zero tail
	// events; the projection must still carry the full state.
	if restartReplay.SnapshotState == nil || len(restartReplay.TailEvents) != 0 {
		t.Fatalf(
			"restart replay = snapshot:%t tail:%d, want snapshot-seeded with no tail",
			restartReplay.SnapshotState != nil,
			len(restartReplay.TailEvents),
		)
	}
	rebuilt, err := identityapp.NewFromSnapshot(nil, restartReplay.SnapshotState, restartReplay.TailEvents)
	if err != nil {
		t.Fatalf("restart identity.NewFromSnapshot() error = %v", err)
	}
	resolved, err := rebuilt.PrincipalGetByIdentifier(tenant.Tenant.ID, principaldomain.Identifier{
		Namespace: "email",
		Value:     "alice@example.com",
	})
	if err != nil || resolved.ID != created.ID {
		t.Fatalf("restart PrincipalGetByIdentifier() = %#v, %v", resolved, err)
	}
	if resolved.Status != principaldomain.StatusSuspended {
		t.Fatalf("restart principal status = %q, want suspended", resolved.Status)
	}
}

// TestRealFYLOLoginSurvivesRestart proves the whole login flow against a real
// runtime: authenticate, kill the process, and verify the session and its
// revocation replay correctly.
func TestRealFYLOLoginSurvivesRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}
	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	root, err := os.MkdirTemp("", "sesame-login-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client, err := fyloadapter.Start(ctx, config)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	ledger, events, err := securityledger.Open(ctx, client)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	service, err := identityapp.New(ledger, events)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}

	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "login@example.com"}
	principal, err := service.PrincipalCreate(
		ctx, tenant.Tenant.ID, principaldomain.KindHuman, identifier, "test:integration")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	const password = "correct horse battery staple"
	if err := service.PasswordSet(ctx, principal.ID, password, "test:integration"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}

	begun, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test:integration")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID, password, "test:integration"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	issued, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test:integration")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	// Die without a clean shutdown.
	if err := client.Crash(); err != nil {
		t.Fatalf("Crash() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	restarted, err := fyloadapter.Start(ctx, config)
	if err != nil {
		t.Fatalf("restart Start() error = %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	restartedLedger, replayed, err := securityledger.Open(ctx, restarted)
	if err != nil {
		t.Fatalf("restart Open() error = %v", err)
	}
	rebuilt, err := identityapp.New(restartedLedger, replayed)
	if err != nil {
		t.Fatalf("restart identity.New() error = %v", err)
	}

	// The session issued before the crash still verifies.
	session, err := rebuilt.SessionVerify(issued.SessionID, issued.Secret)
	if err != nil || session.PrincipalID != principal.ID {
		t.Fatalf("replayed SessionVerify() = %#v, %v", session, err)
	}
	// The password verifier survived, so a fresh login works.
	nextBegun, err := rebuilt.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test:integration")
	if err != nil {
		t.Fatalf("replayed AuthenticationBegin() error = %v", err)
	}
	if _, err := rebuilt.AuthenticationVerifyPassword(ctx, nextBegun.TransactionID, password, "test:integration"); err != nil {
		t.Fatalf("replayed AuthenticationVerifyPassword() error = %v", err)
	}
	// Revocation is durable across another replay.
	if err := rebuilt.SessionRevoke(ctx, issued.SessionID, "test", "test:integration"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	_, finalEvents, err := securityledger.Open(ctx, restarted)
	if err != nil {
		t.Fatalf("final Open() error = %v", err)
	}
	final, err := identityapp.New(nil, finalEvents)
	if err != nil {
		t.Fatalf("final identity.New() error = %v", err)
	}
	if _, err := final.SessionVerify(issued.SessionID, issued.Secret); !errors.Is(err, identityapp.ErrSessionInactive) {
		t.Fatalf("revoked session after replay: %v", err)
	}
}

// TestRealFYLOTOTPReplayRefusedAcrossRestart proves the second factor's
// central property against a real runtime: a spent code stays spent after a
// forced process death, so an observed code cannot be replayed by restarting
// the engine.
func TestRealFYLOTOTPReplayRefusedAcrossRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}
	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	root, err := os.MkdirTemp("", "sesame-totp-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	secretsKey := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	for index := range secretsKey {
		secretsKey[index] = byte(index + 11)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	open := func() (*fyloadapter.Client, *identityapp.Service) {
		t.Helper()
		client, err := fyloadapter.Start(ctx, config)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		ledger, events, err := securityledger.Open(ctx, client)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		service, err := identityapp.New(ledger, events)
		if err != nil {
			t.Fatalf("identity.New() error = %v", err)
		}
		service.UseSecretsKey(secretsKey)
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "mfa@example.com"}
	principal, err := service.PrincipalCreate(
		ctx, tenant.Tenant.ID, principaldomain.KindHuman, identifier, "test:integration")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	const password = "correct horse battery staple"
	if err := service.PasswordSet(ctx, principal.ID, password, "test:integration"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}

	enrollment, err := service.TOTPEnroll(ctx, principal.ID, "SESAME", "test:integration")
	if err != nil {
		t.Fatalf("TOTPEnroll() error = %v", err)
	}
	activation, _ := authenticatordomain.TOTPCode(
		enrollment.Secret, authenticatordomain.TOTPCounter(now))
	if err := service.TOTPActivate(ctx, principal.ID, activation, "test:integration"); err != nil {
		t.Fatalf("TOTPActivate() error = %v", err)
	}

	now = now.Add(authenticatordomain.TOTPPeriodSeconds * time.Second)
	code, _ := authenticatordomain.TOTPCode(enrollment.Secret, authenticatordomain.TOTPCounter(now))

	login := func(service *identityapp.Service) identityapp.AuthenticationResult {
		t.Helper()
		begun, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test:integration")
		if err != nil {
			t.Fatalf("AuthenticationBegin() error = %v", err)
		}
		if _, err := service.AuthenticationVerifyPassword(
			ctx, begun.TransactionID, password, "test:integration"); err != nil {
			t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
		}
		result, err := service.AuthenticationVerifyTOTP(ctx, begun.TransactionID, code, "test:integration")
		if err != nil {
			t.Fatalf("AuthenticationVerifyTOTP() error = %v", err)
		}
		return result
	}

	if first := login(service); first.Assurance != "mfa" {
		t.Fatalf("first TOTP use = %#v", first)
	}

	// Die without a clean shutdown, then try the same still-valid code again.
	if err := client.Crash(); err != nil {
		t.Fatalf("Crash() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	restarted, rebuilt := open()
	t.Cleanup(func() { _ = restarted.Close() })
	if replayed := login(rebuilt); replayed.Assurance == "mfa" {
		t.Fatal("a spent TOTP code was accepted after a restart")
	}

	// A fresh code still works, so the refusal is replay-specific rather
	// than the factor being broken.
	now = now.Add(authenticatordomain.TOTPPeriodSeconds * time.Second)
	code, _ = authenticatordomain.TOTPCode(enrollment.Secret, authenticatordomain.TOTPCounter(now))
	if fresh := login(rebuilt); fresh.Assurance != "mfa" {
		t.Fatalf("a fresh code after restart = %#v", fresh)
	}
}
