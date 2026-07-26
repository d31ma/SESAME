package authentication

import (
	"strings"
	"testing"
	"time"
)

func TestIDGeneration(t *testing.T) {
	t.Parallel()

	first, err := NewID()
	if err != nil || ValidateID(first) != nil {
		t.Fatalf("NewID() = %q, %v", first, err)
	}
	second, _ := NewID()
	if first == second {
		t.Fatal("NewID() returned the same value twice")
	}
	for _, id := range []string{"", "atx_", "ses_" + strings.Repeat("a", 32), "atx_" + strings.Repeat("z", 32)} {
		if err := ValidateID(id); err == nil {
			t.Fatalf("ValidateID(%q) accepted an invalid ID", id)
		}
	}
}

func TestValidateTransition(t *testing.T) {
	t.Parallel()

	permitted := [][2]string{
		{StateStarted, StateAwaitingFactor},
		{StateStarted, StateFailed},
		{StateAwaitingFactor, StateAwaitingFactor},
		{StateAwaitingFactor, StateCompleted},
		{StateAwaitingFactor, StateFailed},
	}
	for _, transition := range permitted {
		if err := ValidateTransition(transition[0], transition[1]); err != nil {
			t.Fatalf("ValidateTransition(%s, %s) error = %v", transition[0], transition[1], err)
		}
	}

	rejected := [][2]string{
		{StateStarted, StateCompleted}, // a factor must be verified first
		{StateCompleted, StateFailed},  // terminal states never move
		{StateFailed, StateAwaitingFactor},
		{StateCompleted, StateCompleted},
		{"invented", StateCompleted},
		{StateAwaitingFactor, "invented"},
	}
	for _, transition := range rejected {
		if err := ValidateTransition(transition[0], transition[1]); err == nil {
			t.Fatalf("ValidateTransition(%s, %s) permitted an illegal transition", transition[0], transition[1])
		}
	}
}

func TestCanAttemptFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	fresh := Transaction{
		State:     StateAwaitingFactor,
		ExpiresAt: now.Add(Lifetime).Format(time.RFC3339Nano),
	}
	if allowed, _ := fresh.CanAttempt(now); !allowed {
		t.Fatal("a fresh transaction cannot attempt")
	}

	expired := fresh
	expired.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	if allowed, reason := expired.CanAttempt(now); allowed || reason != ReasonExpired {
		t.Fatalf("expired transaction = %t, %q", allowed, reason)
	}

	// An unreadable bound is expired, never unbounded.
	unreadable := fresh
	unreadable.ExpiresAt = "whenever"
	if allowed, reason := unreadable.CanAttempt(now); allowed || reason != ReasonExpired {
		t.Fatalf("unparseable expiry = %t, %q", allowed, reason)
	}

	exhausted := fresh
	exhausted.Attempts = MaxAttempts
	if allowed, reason := exhausted.CanAttempt(now); allowed || reason != ReasonAttemptsExhausted {
		t.Fatalf("exhausted transaction = %t, %q", allowed, reason)
	}

	for _, state := range []string{StateCompleted, StateFailed} {
		terminal := fresh
		terminal.State = state
		terminal.FailureCode = ReasonInvalidCredentials
		if allowed, _ := terminal.CanAttempt(now); allowed {
			t.Fatalf("terminal state %q accepted an attempt", state)
		}
		if !Terminal(state) {
			t.Fatalf("state %q is not terminal", state)
		}
	}
	for _, state := range []string{StateStarted, StateAwaitingFactor} {
		if Terminal(state) {
			t.Fatalf("state %q is terminal", state)
		}
	}
}
