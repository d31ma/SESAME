package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
)

func totpFixture(t *testing.T) (authenticationFixture, func() time.Time, *time.Time) {
	t.Helper()

	fixture := newAuthenticationFixture(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := func() time.Time { return now }
	fixture.service.UseClock(clock)

	key := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	for index := range key {
		key[index] = byte(index + 7)
	}
	fixture.service.UseSecretsKey(key)
	return fixture, clock, &now
}

// enrollAndActivate walks the two-step enrollment and returns the secret.
func enrollAndActivate(t *testing.T, fixture authenticationFixture, now time.Time) string {
	t.Helper()

	enrollment, err := fixture.service.TOTPEnroll(
		context.Background(), fixture.alice, "SESAME", "test")
	if err != nil {
		t.Fatalf("TOTPEnroll() error = %v", err)
	}
	code, err := authenticatordomain.TOTPCode(
		enrollment.Secret, authenticatordomain.TOTPCounter(now))
	if err != nil {
		t.Fatalf("TOTPCode() error = %v", err)
	}
	if err := fixture.service.TOTPActivate(
		context.Background(), fixture.alice, code, "test"); err != nil {
		t.Fatalf("TOTPActivate() error = %v", err)
	}
	return enrollment.Secret
}

func TestTOTPEnrollmentRequiresProofBeforeUse(t *testing.T) {
	t.Parallel()

	fixture, _, now := totpFixture(t)
	ctx := context.Background()

	enrollment, err := fixture.service.TOTPEnroll(ctx, fixture.alice, "SESAME", "test")
	if err != nil {
		t.Fatalf("TOTPEnroll() error = %v", err)
	}
	if enrollment.Secret == "" || !strings.HasPrefix(enrollment.ProvisioningURI, "otpauth://totp/") {
		t.Fatalf("TOTPEnroll() = %#v", enrollment)
	}

	// An enrolled but unactivated factor cannot satisfy authentication.
	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := fixture.service.AuthenticationVerifyPassword(
		ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	code, _ := authenticatordomain.TOTPCode(
		enrollment.Secret, authenticatordomain.TOTPCounter(*now))
	result, err := fixture.service.AuthenticationVerifyTOTP(ctx, begun.TransactionID, code, "test")
	if err != nil {
		t.Fatalf("AuthenticationVerifyTOTP() error = %v", err)
	}
	if result.Assurance == authndomain.AssuranceMFA {
		t.Fatal("an unactivated authenticator satisfied a second factor")
	}

	// A wrong code cannot activate it either.
	if err := fixture.service.TOTPActivate(ctx, fixture.alice, "000000", "test"); !errors.Is(err, ErrTOTPInvalidCode) {
		t.Fatalf("TOTPActivate(wrong) error = %v", err)
	}
	if err := fixture.service.TOTPActivate(ctx, fixture.alice, code, "test"); err != nil {
		t.Fatalf("TOTPActivate() error = %v", err)
	}
	// Re-enrolling over an active factor is refused.
	if _, err := fixture.service.TOTPEnroll(ctx, fixture.alice, "SESAME", "test"); !errors.Is(err, ErrTOTPAlreadyActive) {
		t.Fatalf("re-enroll error = %v", err)
	}
}

func TestTOTPRaisesAssuranceToMFA(t *testing.T) {
	t.Parallel()

	fixture, _, now := totpFixture(t)
	ctx := context.Background()
	secret := enrollAndActivate(t, fixture, *now)

	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	verified, err := fixture.service.AuthenticationVerifyPassword(
		ctx, begun.TransactionID, goodPassword, "test")
	if err != nil || verified.Assurance != authndomain.AssurancePassword {
		t.Fatalf("password factor = %#v, %v", verified, err)
	}

	// Advance a step so the activation counter is not reused.
	*now = now.Add(authenticatordomain.TOTPPeriodSeconds * time.Second)
	code, _ := authenticatordomain.TOTPCode(secret, authenticatordomain.TOTPCounter(*now))
	result, err := fixture.service.AuthenticationVerifyTOTP(ctx, begun.TransactionID, code, "test")
	if err != nil || result.Assurance != authndomain.AssuranceMFA {
		t.Fatalf("TOTP factor = %#v, %v", result, err)
	}

	issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil || issued.Assurance != authndomain.AssuranceMFA {
		t.Fatalf("AuthenticationComplete() = %#v, %v", issued, err)
	}
	session, err := fixture.service.SessionVerify(issued.SessionID, issued.Secret)
	if err != nil || session.Assurance != authndomain.AssuranceMFA {
		t.Fatalf("session assurance = %#v, %v", session, err)
	}
}

// TestTOTPRefusesReplayWithinItsWindow is the property that separates a real
// second factor from a decorative one.
func TestTOTPRefusesReplayWithinItsWindow(t *testing.T) {
	t.Parallel()

	fixture, _, now := totpFixture(t)
	ctx := context.Background()
	secret := enrollAndActivate(t, fixture, *now)
	*now = now.Add(authenticatordomain.TOTPPeriodSeconds * time.Second)
	code, _ := authenticatordomain.TOTPCode(secret, authenticatordomain.TOTPCounter(*now))

	authenticate := func() (AuthenticationResult, error) {
		begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
		if _, err := fixture.service.AuthenticationVerifyPassword(
			ctx, begun.TransactionID, goodPassword, "test"); err != nil {
			t.Fatalf("password factor error = %v", err)
		}
		return fixture.service.AuthenticationVerifyTOTP(ctx, begun.TransactionID, code, "test")
	}

	first, err := authenticate()
	if err != nil || first.Assurance != authndomain.AssuranceMFA {
		t.Fatalf("first use = %#v, %v", first, err)
	}

	// The clock has not moved, so the code is still inside its own window —
	// and must be refused anyway.
	second, err := authenticate()
	if err != nil {
		t.Fatalf("replay attempt error = %v", err)
	}
	if second.Assurance == authndomain.AssuranceMFA {
		t.Fatal("a TOTP code was accepted twice inside its own window")
	}

	// The refusal survives a complete replay from the ledger.
	replayed, err := New(fixture.ledger, fixture.ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	replayed.UseClock(func() time.Time { return *now })
	key := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	for index := range key {
		key[index] = byte(index + 7)
	}
	replayed.UseSecretsKey(key)

	begun, _ := replayed.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := replayed.AuthenticationVerifyPassword(
		ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("replayed password factor error = %v", err)
	}
	afterReplay, err := replayed.AuthenticationVerifyTOTP(ctx, begun.TransactionID, code, "test")
	if err != nil {
		t.Fatalf("replayed TOTP error = %v", err)
	}
	if afterReplay.Assurance == authndomain.AssuranceMFA {
		t.Fatal("a spent TOTP counter was forgotten across replay")
	}
}

func TestTOTPRequiresAFirstFactor(t *testing.T) {
	t.Parallel()

	fixture, _, now := totpFixture(t)
	ctx := context.Background()
	secret := enrollAndActivate(t, fixture, *now)
	*now = now.Add(authenticatordomain.TOTPPeriodSeconds * time.Second)
	code, _ := authenticatordomain.TOTPCode(secret, authenticatordomain.TOTPCounter(*now))

	// A code alone proves possession of a device, not of the account.
	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := fixture.service.AuthenticationVerifyTOTP(
		ctx, begun.TransactionID, code, "test"); !errors.Is(err, ErrTransactionClosed) {
		t.Fatalf("TOTP without a first factor error = %v", err)
	}
	// And the code is not spent by the refusal, so it still works properly.
	if _, err := fixture.service.AuthenticationVerifyPassword(
		ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("password factor error = %v", err)
	}
	result, err := fixture.service.AuthenticationVerifyTOTP(ctx, begun.TransactionID, code, "test")
	if err != nil || result.Assurance != authndomain.AssuranceMFA {
		t.Fatalf("TOTP after password = %#v, %v", result, err)
	}
}

func TestTOTPFailsClosedWithoutASealingKey(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	// No UseSecretsKey: a deployment-less process must not store a shared
	// secret it cannot protect.
	if _, err := fixture.service.TOTPEnroll(
		context.Background(), fixture.alice, "SESAME", "test",
	); !errors.Is(err, authenticatordomain.ErrNoSealingKey) {
		t.Fatalf("TOTPEnroll without a key error = %v", err)
	}
}

// TestTOTPSecretNeverReachesTheLedger is the canary for the slice.
func TestTOTPSecretNeverReachesTheLedger(t *testing.T) {
	t.Parallel()

	fixture, _, now := totpFixture(t)
	secret := enrollAndActivate(t, fixture, *now)

	for _, event := range fixture.ledger.events {
		if strings.Contains(string(event.Payload), secret) {
			t.Fatalf("event %s (sequence %d) leaks the TOTP secret", event.Type, event.Sequence)
		}
	}
	encoded, err := json.Marshal(fixture.service.ExportState())
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("snapshot state leaks the TOTP secret")
	}
	// The sealed form is present, so the factor still works after restore.
	if !strings.Contains(string(encoded), "sealed.v1.") {
		t.Fatal("snapshot state does not carry the sealed secret")
	}
}
