package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
)

// loginWith authenticates and optionally supplies a second factor, returning
// the issued session.
func loginWith(
	t *testing.T,
	fixture authenticationFixture,
	secondFactor func(transactionID string),
) IssuedSession {
	t.Helper()

	ctx := context.Background()
	begun, err := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := fixture.service.AuthenticationVerifyPassword(
		ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	if secondFactor != nil {
		secondFactor(begun.TransactionID)
	}
	issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	return issued
}

// TestStepUpRequiresProvenAssurance is the point of the whole slice: a
// permission can demand MFA, and the demand is satisfied by a session the
// engine verified rather than by a claim the caller made.
func TestStepUpRequiresProvenAssurance(t *testing.T) {
	t.Parallel()

	fixture, _, now := totpFixture(t)
	ctx := context.Background()
	secret := enrollAndActivate(t, fixture, *now)

	role, err := fixture.service.RoleCreate(ctx, fixture.tenant, "treasurer", []authzdomain.Permission{
		{
			Action:     "billing:write",
			Resource:   "*",
			Conditions: map[string]string{ContextAssurance: authndomain.AssuranceMFA},
		},
	}, "test")
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	if _, err := fixture.service.GrantCreate(ctx, fixture.tenant, fixture.alice, role.ID, "test"); err != nil {
		t.Fatalf("GrantCreate() error = %v", err)
	}

	// A password-only session is denied and told exactly what is missing.
	passwordOnly := loginWith(t, fixture, nil)
	decision, err := fixture.service.Decide(DecisionRequest{
		Action:        "billing:write",
		Resource:      "ledger:2026",
		SessionID:     passwordOnly.SessionID,
		SessionSecret: passwordOnly.Secret,
	}, nil)
	if err != nil {
		t.Fatalf("password-only Decide() error = %v", err)
	}
	if decision.Decision != DecisionDeny || decision.ReasonCode != ReasonDenyNoGrant {
		t.Fatalf("password-only decision = %#v", decision)
	}

	// The same principal with a second factor is allowed.
	*now = now.Add(authenticatordomain.TOTPPeriodSeconds * time.Second)
	code, _ := authenticatordomain.TOTPCode(secret, authenticatordomain.TOTPCounter(*now))
	stepped := loginWith(t, fixture, func(transactionID string) {
		if _, err := fixture.service.AuthenticationVerifyTOTP(ctx, transactionID, code, "test"); err != nil {
			t.Fatalf("AuthenticationVerifyTOTP() error = %v", err)
		}
	})
	if stepped.Assurance != authndomain.AssuranceMFA {
		t.Fatalf("stepped-up session assurance = %q", stepped.Assurance)
	}
	decision, err = fixture.service.Decide(DecisionRequest{
		Action:        "billing:write",
		Resource:      "ledger:2026",
		SessionID:     stepped.SessionID,
		SessionSecret: stepped.Secret,
	}, nil)
	if err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("stepped-up decision = %#v, %v", decision, err)
	}
}

// TestStepUpCannotBeAsserted is the property that makes the derived context
// trustworthy: a caller cannot simply claim the assurance it lacks.
func TestStepUpCannotBeAsserted(t *testing.T) {
	t.Parallel()

	fixture, _, _ := totpFixture(t)
	ctx := context.Background()
	role, err := fixture.service.RoleCreate(ctx, fixture.tenant, "treasurer", []authzdomain.Permission{
		{
			Action:     "billing:write",
			Resource:   "*",
			Conditions: map[string]string{ContextAssurance: authndomain.AssuranceMFA},
		},
	}, "test")
	if err != nil {
		t.Fatalf("RoleCreate() error = %v", err)
	}
	if _, err := fixture.service.GrantCreate(ctx, fixture.tenant, fixture.alice, role.ID, "test"); err != nil {
		t.Fatalf("GrantCreate() error = %v", err)
	}

	// Supplying the reserved attribute directly is refused outright, rather
	// than being silently ignored: a policy author must be able to trust
	// what the prefix means.
	_, err = fixture.service.Decide(DecisionRequest{
		TenantID:    fixture.tenant,
		PrincipalID: fixture.alice,
		Action:      "billing:write",
		Resource:    "ledger:2026",
		Context:     map[string]string{ContextAssurance: authndomain.AssuranceMFA},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "verified session") {
		t.Fatalf("asserted assurance error = %v", err)
	}

	// Without a session the attribute is simply absent, and the decision
	// names it so the host knows to step up.
	decision, err := fixture.service.Decide(DecisionRequest{
		TenantID:    fixture.tenant,
		PrincipalID: fixture.alice,
		Action:      "billing:write",
		Resource:    "ledger:2026",
	}, nil)
	if err != nil {
		t.Fatalf("sessionless Decide() error = %v", err)
	}
	if decision.ReasonCode != ReasonDenyMissingContext || decision.MissingKey != ContextAssurance {
		t.Fatalf("sessionless decision = %#v", decision)
	}
}

func TestDecisionSessionMustBeUsable(t *testing.T) {
	t.Parallel()

	fixture, _, _ := totpFixture(t)
	ctx := context.Background()
	issued := loginWith(t, fixture, nil)

	request := DecisionRequest{
		Action:        "doc:read",
		Resource:      "project:alpha",
		SessionID:     issued.SessionID,
		SessionSecret: issued.Secret,
	}
	// A valid session with no grant is an ordinary deny, not a session error.
	decision, err := fixture.service.Decide(request, nil)
	if err != nil || decision.ReasonCode != ReasonDenyNoGrant {
		t.Fatalf("valid session decision = %#v, %v", decision, err)
	}

	// A wrong secret, an unknown session, and a mismatched principal all
	// deny as session failures rather than answering from a session the
	// caller does not hold.
	wrongSecret := request
	wrongSecret.SessionSecret = "nope"
	if decision, _ := fixture.service.Decide(wrongSecret, nil); decision.ReasonCode != ReasonDenySessionInvalid {
		t.Fatalf("wrong secret decision = %#v", decision)
	}
	unknown := request
	unknown.SessionID = "ses_00000000000000000000000000000000"
	if decision, _ := fixture.service.Decide(unknown, nil); decision.ReasonCode != ReasonDenySessionInvalid {
		t.Fatalf("unknown session decision = %#v", decision)
	}
	mismatched := request
	mismatched.PrincipalID = "prn_00000000000000000000000000000000"
	if decision, _ := fixture.service.Decide(mismatched, nil); decision.ReasonCode != ReasonDenySessionInvalid {
		t.Fatalf("mismatched principal decision = %#v", decision)
	}

	// Revoking the session denies immediately.
	if err := fixture.service.SessionRevoke(ctx, issued.SessionID, "test", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	if decision, _ := fixture.service.Decide(request, nil); decision.ReasonCode != ReasonDenySessionInvalid {
		t.Fatalf("revoked session decision = %#v", decision)
	}
}

func TestRecoveryCodesAreSingleUseSecondFactors(t *testing.T) {
	t.Parallel()

	fixture, _, _ := totpFixture(t)
	ctx := context.Background()

	set, err := fixture.service.RecoveryCodesIssue(ctx, fixture.alice, "test")
	if err != nil {
		t.Fatalf("RecoveryCodesIssue() error = %v", err)
	}
	if len(set.Codes) != authenticatordomain.RecoveryCodeCount {
		t.Fatalf("issued %d codes", len(set.Codes))
	}
	remaining, err := fixture.service.RecoveryCodesRemaining(fixture.alice)
	if err != nil || remaining != authenticatordomain.RecoveryCodeCount {
		t.Fatalf("remaining = %d, %v", remaining, err)
	}

	// A recovery code raises assurance to MFA, standing in for the lost
	// device.
	code := set.Codes[0]
	stepped := loginWith(t, fixture, func(transactionID string) {
		result, err := fixture.service.AuthenticationVerifyRecoveryCode(ctx, transactionID, code, "test")
		if err != nil || result.Assurance != authndomain.AssuranceMFA {
			t.Fatalf("AuthenticationVerifyRecoveryCode() = %#v, %v", result, err)
		}
	})
	if stepped.Assurance != authndomain.AssuranceMFA {
		t.Fatalf("recovery session assurance = %q", stepped.Assurance)
	}
	if remaining, _ := fixture.service.RecoveryCodesRemaining(fixture.alice); remaining != authenticatordomain.RecoveryCodeCount-1 {
		t.Fatalf("remaining after use = %d", remaining)
	}

	// The same code cannot be used twice, and the refusal survives replay.
	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := fixture.service.AuthenticationVerifyPassword(
		ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("password factor error = %v", err)
	}
	reused, err := fixture.service.AuthenticationVerifyRecoveryCode(ctx, begun.TransactionID, code, "test")
	if err != nil {
		t.Fatalf("reuse error = %v", err)
	}
	if reused.Assurance == authndomain.AssuranceMFA {
		t.Fatal("a recovery code was accepted twice")
	}

	replayed, err := New(fixture.ledger, fixture.ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	if remaining, _ := replayed.RecoveryCodesRemaining(fixture.alice); remaining != authenticatordomain.RecoveryCodeCount-1 {
		t.Fatalf("replayed remaining = %d", remaining)
	}

	// Reissuing retires every previous code.
	reissued, err := fixture.service.RecoveryCodesIssue(ctx, fixture.alice, "test")
	if err != nil {
		t.Fatalf("reissue error = %v", err)
	}
	if remaining, _ := fixture.service.RecoveryCodesRemaining(fixture.alice); remaining != authenticatordomain.RecoveryCodeCount {
		t.Fatalf("remaining after reissue = %d", remaining)
	}
	begun, _ = fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := fixture.service.AuthenticationVerifyPassword(
		ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("password factor error = %v", err)
	}
	retired, err := fixture.service.AuthenticationVerifyRecoveryCode(ctx, begun.TransactionID, set.Codes[1], "test")
	if err != nil {
		t.Fatalf("retired code error = %v", err)
	}
	if retired.Assurance == authndomain.AssuranceMFA {
		t.Fatal("a retired code from the previous set was accepted")
	}
	// A code from the new set still works.
	if _, err := fixture.service.AuthenticationVerifyRecoveryCode(
		ctx, begun.TransactionID, reissued.Codes[0], "test"); err != nil {
		t.Fatalf("new-set code error = %v", err)
	}
}

func TestRecoveryCodesRequireAFirstFactorAndNeverLeak(t *testing.T) {
	t.Parallel()

	fixture, _, _ := totpFixture(t)
	ctx := context.Background()
	set, err := fixture.service.RecoveryCodesIssue(ctx, fixture.alice, "test")
	if err != nil {
		t.Fatalf("RecoveryCodesIssue() error = %v", err)
	}

	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if _, err := fixture.service.AuthenticationVerifyRecoveryCode(
		ctx, begun.TransactionID, set.Codes[0], "test"); !errors.Is(err, ErrTransactionClosed) {
		t.Fatalf("recovery code without a first factor error = %v", err)
	}

	// No event or snapshot may carry a plaintext code.
	for _, event := range fixture.ledger.events {
		for _, code := range set.Codes {
			if strings.Contains(string(event.Payload), code) {
				t.Fatalf("event %s leaks a recovery code", event.Type)
			}
		}
	}
	encoded := mustEncode(t, fixture.service.ExportState())
	for _, code := range set.Codes {
		if strings.Contains(encoded, code) {
			t.Fatal("snapshot state leaks a recovery code")
		}
	}
}
