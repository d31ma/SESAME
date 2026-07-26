package session

import (
	"strings"
	"testing"
	"time"
)

func TestSecretsAreRandomAndStoredOneWay(t *testing.T) {
	t.Parallel()

	secret, digest, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	if len(secret) < 40 {
		t.Fatalf("secret length = %d, want a 256-bit value", len(secret))
	}
	if strings.Contains(digest, secret) {
		t.Fatal("digest contains the secret")
	}
	if !VerifySecret(digest, secret) {
		t.Fatal("VerifySecret rejected the issued secret")
	}
	if VerifySecret(digest, secret+"x") || VerifySecret(digest, "") {
		t.Fatal("VerifySecret accepted a wrong secret")
	}

	otherSecret, otherDigest, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret() error = %v", err)
	}
	if otherSecret == secret || otherDigest == digest {
		t.Fatal("two secrets collided; the source is not random")
	}
	if VerifySecret(digest, otherSecret) {
		t.Fatal("VerifySecret matched a different secret")
	}
}

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
	// A session ID is a handle, never a secret: it must not be accepted as
	// one, and the secret must not be accepted as an ID.
	secret, digest, _ := NewSecret()
	if VerifySecret(digest, first) {
		t.Fatal("a session ID verified as a session secret")
	}
	if ValidateID(secret) == nil {
		t.Fatal("a session secret validated as a session ID")
	}
	for _, id := range []string{"", "ses_", "prn_" + strings.Repeat("a", 32), "ses_" + strings.Repeat("z", 32)} {
		if err := ValidateID(id); err == nil {
			t.Fatalf("ValidateID(%q) accepted an invalid ID", id)
		}
	}
}

func TestLifetimeClamping(t *testing.T) {
	t.Parallel()

	if lifetime, err := Lifetime(0); err != nil || lifetime != DefaultLifetime {
		t.Fatalf("Lifetime(0) = %s, %v", lifetime, err)
	}
	if lifetime, err := Lifetime(time.Hour); err != nil || lifetime != time.Hour {
		t.Fatalf("Lifetime(1h) = %s, %v", lifetime, err)
	}
	if _, err := Lifetime(time.Second); err == nil {
		t.Fatal("Lifetime accepted a sub-minute lifetime")
	}
	if _, err := Lifetime(MaxLifetime + time.Hour); err == nil {
		t.Fatal("Lifetime accepted an unbounded lifetime")
	}
}

func TestActiveFailsClosed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	active := Session{
		Status:    StatusActive,
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	if !active.Active(now) {
		t.Fatal("an unexpired active session is not active")
	}

	expired := active
	expired.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	if expired.Active(now) {
		t.Fatal("an expired session is active")
	}

	revoked := active
	revoked.Status = StatusRevoked
	if revoked.Active(now) {
		t.Fatal("a revoked session is active")
	}

	// An unreadable bound denies rather than being treated as no bound.
	unreadable := active
	unreadable.ExpiresAt = "not-a-timestamp"
	if unreadable.Active(now) {
		t.Fatal("a session with an unparseable expiry is active")
	}
	empty := active
	empty.ExpiresAt = ""
	if empty.Active(now) {
		t.Fatal("a session with no expiry is active")
	}
}
