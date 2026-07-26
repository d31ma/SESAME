package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
)

const goodPassword = "correct horse battery staple"

type authenticationFixture struct {
	service  *Service
	ledger   *memoryLedger
	tenant   string
	alice    string
	identity principaldomain.Identifier
}

func newAuthenticationFixture(t *testing.T) authenticationFixture {
	t.Helper()

	service, ledger, tenantID := bootstrapService(t)
	identifier := principaldomain.Identifier{Namespace: "email", Value: "alice@example.com"}
	alice, err := service.PrincipalCreate(
		context.Background(), tenantID, principaldomain.KindHuman, identifier, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(context.Background(), alice.ID, goodPassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	return authenticationFixture{
		service:  service,
		ledger:   ledger,
		tenant:   tenantID,
		alice:    alice.ID,
		identity: identifier,
	}
}

func TestAuthenticationHappyPathIssuesUsableSession(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	ctx := context.Background()

	begun, err := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if err != nil || begun.State != authndomain.StateAwaitingFactor {
		t.Fatalf("AuthenticationBegin() = %#v, %v", begun, err)
	}

	verified, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test")
	if err != nil || verified.Assurance != authndomain.AssurancePassword {
		t.Fatalf("AuthenticationVerifyPassword() = %#v, %v", verified, err)
	}

	issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, 0, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	if issued.Secret == "" || issued.PrincipalID != fixture.alice {
		t.Fatalf("AuthenticationComplete() = %#v", issued)
	}

	verifiedSession, err := fixture.service.SessionVerify(issued.SessionID, issued.Secret)
	if err != nil || verifiedSession.PrincipalID != fixture.alice {
		t.Fatalf("SessionVerify() = %#v, %v", verifiedSession, err)
	}
	if _, err := fixture.service.SessionVerify(issued.SessionID, issued.Secret+"x"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("SessionVerify(wrong secret) error = %v", err)
	}

	// A completed transaction cannot issue a second session.
	if _, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, 0, "test"); !errors.Is(err, ErrTransactionClosed) {
		t.Fatalf("second AuthenticationComplete() error = %v", err)
	}
}

func TestAuthenticationDoesNotRevealIdentifierExistence(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	ctx := context.Background()

	unknown := principaldomain.Identifier{Namespace: "email", Value: "nobody@example.com"}
	begun, err := fixture.service.AuthenticationBegin(ctx, fixture.tenant, unknown, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin(unknown) error = %v", err)
	}
	if begun.State != authndomain.StateAwaitingFactor {
		t.Fatalf("unknown identifier produced state %q, revealing it does not exist", begun.State)
	}

	// The wrong-password result for an unknown identifier is identical to
	// the wrong-password result for a known one.
	unknownResult, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test")
	if err != nil {
		t.Fatalf("AuthenticationVerifyPassword(unknown) error = %v", err)
	}
	knownBegun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	knownResult, err := fixture.service.AuthenticationVerifyPassword(ctx, knownBegun.TransactionID, "wrong password value", "test")
	if err != nil {
		t.Fatalf("AuthenticationVerifyPassword(known, wrong) error = %v", err)
	}
	if unknownResult.State != knownResult.State ||
		unknownResult.FailureCode != knownResult.FailureCode ||
		unknownResult.AttemptsLeft != knownResult.AttemptsLeft {
		t.Fatalf("unknown %#v differs from known-wrong %#v", unknownResult, knownResult)
	}

	// Even the correct password cannot complete a transaction that resolved
	// no principal.
	if _, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, 0, "test"); !errors.Is(err, ErrTransactionClosed) {
		t.Fatalf("unresolved AuthenticationComplete() error = %v", err)
	}
}

func TestAuthenticationBoundsAttempts(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	ctx := context.Background()
	begun, err := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}

	for attempt := 1; attempt <= authndomain.MaxAttempts; attempt++ {
		result, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, "wrong password value", "test")
		if err != nil {
			t.Fatalf("attempt %d error = %v", attempt, err)
		}
		if attempt < authndomain.MaxAttempts {
			if result.State != authndomain.StateAwaitingFactor || result.AttemptsLeft != authndomain.MaxAttempts-attempt {
				t.Fatalf("attempt %d = %#v", attempt, result)
			}
			continue
		}
		if result.State != authndomain.StateFailed || result.FailureCode != authndomain.ReasonAttemptsExhausted {
			t.Fatalf("final attempt = %#v", result)
		}
	}

	// The correct password no longer helps.
	if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test"); !errors.Is(err, ErrTransactionClosed) {
		t.Fatalf("post-exhaustion attempt error = %v", err)
	}
	if _, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, 0, "test"); !errors.Is(err, ErrTransactionClosed) {
		t.Fatalf("post-exhaustion complete error = %v", err)
	}
}

func TestAuthenticationExpiryFailsClosed(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	fixture.service.UseClock(func() time.Time { return now })

	begun, err := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	now = now.Add(authndomain.Lifetime + time.Second)

	result, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test")
	if !errors.Is(err, ErrTransactionClosed) {
		t.Fatalf("expired attempt error = %v", err)
	}
	if result.FailureCode != authndomain.ReasonExpired {
		t.Fatalf("expired attempt = %#v", result)
	}
}

func TestSessionRevocationAndSuspensionDenyDurably(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	ctx := context.Background()

	authenticate := func() IssuedSession {
		t.Helper()
		begun, err := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
		if err != nil {
			t.Fatalf("AuthenticationBegin() error = %v", err)
		}
		if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test"); err != nil {
			t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
		}
		issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
		if err != nil {
			t.Fatalf("AuthenticationComplete() error = %v", err)
		}
		return issued
	}

	revoked := authenticate()
	if err := fixture.service.SessionRevoke(ctx, revoked.SessionID, "test", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	if _, err := fixture.service.SessionVerify(revoked.SessionID, revoked.Secret); !errors.Is(err, ErrSessionInactive) {
		t.Fatalf("revoked SessionVerify() error = %v", err)
	}
	// Revocation is idempotent so emergency response can be retried.
	if err := fixture.service.SessionRevoke(ctx, revoked.SessionID, "test", "test"); err != nil {
		t.Fatalf("repeat SessionRevoke() error = %v", err)
	}

	// Suspending the principal denies its live sessions without touching
	// them individually.
	live := authenticate()
	if _, err := fixture.service.SessionVerify(live.SessionID, live.Secret); err != nil {
		t.Fatalf("live SessionVerify() error = %v", err)
	}
	if _, err := fixture.service.PrincipalSuspend(ctx, fixture.alice, "test"); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}
	if _, err := fixture.service.SessionVerify(live.SessionID, live.Secret); !errors.Is(err, ErrSessionInactive) {
		t.Fatalf("suspended-principal SessionVerify() error = %v", err)
	}

	// Both denials survive a complete replay from the ledger alone.
	replayed, err := New(nil, fixture.ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	if _, err := replayed.SessionVerify(revoked.SessionID, revoked.Secret); !errors.Is(err, ErrSessionInactive) {
		t.Fatalf("replayed revoked SessionVerify() error = %v", err)
	}
	if _, err := replayed.SessionVerify(live.SessionID, live.Secret); !errors.Is(err, ErrSessionInactive) {
		t.Fatalf("replayed suspended SessionVerify() error = %v", err)
	}
}

func TestSessionExpiryDenies(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	fixture.service.UseClock(func() time.Time { return now })

	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	if _, err := fixture.service.SessionVerify(issued.SessionID, issued.Secret); err != nil {
		t.Fatalf("fresh SessionVerify() error = %v", err)
	}
	now = now.Add(time.Hour + time.Second)
	if _, err := fixture.service.SessionVerify(issued.SessionID, issued.Secret); !errors.Is(err, ErrSessionInactive) {
		t.Fatalf("expired SessionVerify() error = %v", err)
	}
}

// TestLedgerNeverStoresPlaintextCredentials is the canary for the whole
// slice: no event payload may contain a password or a session secret.
func TestLedgerNeverStoresPlaintextCredentials(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	ctx := context.Background()

	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, "wrong password value", "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword(wrong) error = %v", err)
	}
	if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, 0, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	for _, event := range fixture.ledger.events {
		payload := string(event.Payload)
		for name, secret := range map[string]string{
			"password":       goodPassword,
			"wrong password": "wrong password value",
			"session secret": issued.Secret,
		} {
			if strings.Contains(payload, secret) {
				t.Fatalf("event %s (sequence %d) leaks the %s", event.Type, event.Sequence, name)
			}
		}
		// An identifier is a locator, not a credential, so principal.created
		// stores it by design. Authentication events must not: a failed login
		// would otherwise leave a durable record of what someone typed.
		if strings.HasPrefix(event.Type, "authentication.") &&
			strings.Contains(payload, fixture.identity.Value) {
			t.Fatalf("event %s (sequence %d) records the attempted identifier", event.Type, event.Sequence)
		}
	}

	// The snapshot projection must not leak them either.
	state := fixture.service.ExportState()
	encoded := mustEncode(t, state)
	for _, secret := range []string{goodPassword, issued.Secret} {
		if strings.Contains(encoded, secret) {
			t.Fatal("snapshot state leaks a credential")
		}
	}
	// The stored verifier is present but is one-way, not the password.
	if !strings.Contains(encoded, "$argon2id$") {
		t.Fatal("snapshot state does not carry the password verifier")
	}
}

func TestSessionSecretIsNotDerivedFromAnyIdentifier(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	ctx := context.Background()
	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, 0, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	// No public handle may act as the secret.
	for _, handle := range []string{issued.SessionID, issued.PrincipalID, issued.TenantID, begun.TransactionID} {
		if _, err := fixture.service.SessionVerify(issued.SessionID, handle); err == nil {
			t.Fatalf("handle %q was accepted as a session secret", handle)
		}
	}
	if sessiondomain.Digest(issued.Secret) == issued.SessionID {
		t.Fatal("session ID is derived from the secret")
	}
}

func mustEncode(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(encoded)
}

// TestSnapshotCarriesAuthenticationState is the regression guard for a
// snapshot that forgets a projection: a snapshot-seeded service must accept
// the same session and password a fully replayed one would.
func TestSnapshotCarriesAuthenticationState(t *testing.T) {
	t.Parallel()

	fixture := newAuthenticationFixture(t)
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)
	ctx := context.Background()

	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	// A fresh ledger: the restored service must work from snapshot state
	// alone, without replaying the original events.
	restored, err := NewFromSnapshot(&memoryLedger{}, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	if _, err := restored.SessionVerify(issued.SessionID, issued.Secret); err != nil {
		t.Fatalf("snapshot-seeded SessionVerify() error = %v", err)
	}

	// The restored projection still authenticates the same password, which
	// only holds if the verifier travelled in the snapshot.
	next, err := restored.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if err != nil {
		t.Fatalf("snapshot-seeded AuthenticationBegin() error = %v", err)
	}
	result, err := restored.AuthenticationVerifyPassword(ctx, next.TransactionID, goodPassword, "test")
	if err != nil || result.Assurance != authndomain.AssurancePassword {
		t.Fatalf("snapshot-seeded verify = %#v, %v", result, err)
	}
}
