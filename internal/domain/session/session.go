// Package session defines bounded, revocable authenticated contexts.
//
// A session has two values with different jobs. The ID is a public handle
// that may be logged and stored; the secret is bearer-equivalent, returned
// exactly once at issuance, and stored only as a SHA-256 digest. FYLO and
// TTID identifiers are never used for either, because neither is
// unpredictable.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// EventIssued records an authenticated context coming into existence.
	EventIssued = "session.issued"
	// EventRevoked records a durable, replay-safe revocation.
	EventRevoked = "session.revoked"

	// IDPrefix distinguishes public session identifiers.
	IDPrefix = "ses_"

	// DefaultLifetime bounds a session that names no explicit expiry.
	DefaultLifetime = 12 * time.Hour
	// MaxLifetime is the longest session SESAME will issue.
	MaxLifetime = 720 * time.Hour

	secretBytes = 32
)

// Status values for a session projection.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// Session is one bounded authenticated context. It never carries the
// secret: only the digest of the secret is durable.
type Session struct {
	ID          string `json:"session_id"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	Status      string `json:"status"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	// SecretDigest is omitted when cleared so a public surface that strips
	// it does not advertise the field at all.
	SecretDigest string `json:"secret_digest,omitempty"`
	// Assurance records how the principal proved identity, so a later
	// step-up requirement can be evaluated without re-reading the ledger.
	Assurance string `json:"assurance"`
}

// IssuedPayload is the versioned payload of an EventIssued event.
type IssuedPayload struct {
	SessionID   string `json:"session_id"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	// SecretDigest is omitted when cleared so a public surface that strips
	// it does not advertise the field at all.
	SecretDigest string `json:"secret_digest,omitempty"`
	Assurance    string `json:"assurance"`
}

// RevokedPayload is the versioned payload of an EventRevoked event.
type RevokedPayload struct {
	SessionID string `json:"session_id"`
	TenantID  string `json:"tenant_id"`
	Reason    string `json:"reason"`
}

// NewID returns a random public session identifier.
func NewID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return IDPrefix + hex.EncodeToString(value), nil
}

// ValidateID rejects values that cannot be session identifiers.
func ValidateID(id string) error {
	if !strings.HasPrefix(id, IDPrefix) || len(id) != len(IDPrefix)+32 {
		return errors.New("session ID must be ses_ followed by 32 hex characters")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, IDPrefix)); err != nil {
		return errors.New("session ID must be ses_ followed by 32 hex characters")
	}
	return nil
}

// NewSecret returns a fresh bearer-equivalent session secret and its digest.
// The caller must hand the secret to its owner and keep only the digest.
func NewSecret() (secret string, digest string, err error) {
	value := make([]byte, secretBytes)
	if _, err := rand.Read(value); err != nil {
		return "", "", fmt.Errorf("generate session secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(value)
	return secret, Digest(secret), nil
}

// Digest hashes a session secret for storage and comparison.
//
// SHA-256 without a password-hashing construction is deliberate: the secret
// is 256 bits of uniform randomness, so there is no guessable input space to
// slow an attacker down through, and login-path latency matters.
func Digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// VerifySecret compares a presented secret against a stored digest in
// constant time.
func VerifySecret(storedDigest, presented string) bool {
	return subtle.ConstantTimeCompare([]byte(Digest(presented)), []byte(storedDigest)) == 1
}

// Lifetime clamps a requested session lifetime into the supported range.
func Lifetime(requested time.Duration) (time.Duration, error) {
	if requested == 0 {
		return DefaultLifetime, nil
	}
	if requested < time.Minute {
		return 0, errors.New("session lifetime must be at least one minute")
	}
	if requested > MaxLifetime {
		return 0, fmt.Errorf("session lifetime must not exceed %s", MaxLifetime)
	}
	return requested, nil
}

// Active reports whether a session may still authorize work at the given
// time. Expiry and revocation both deny, and an unparseable expiry denies:
// a session whose bound cannot be read is not a session with no bound.
func (s Session) Active(now time.Time) bool {
	if s.Status != StatusActive {
		return false
	}
	expiry, err := time.Parse(time.RFC3339Nano, s.ExpiresAt)
	if err != nil {
		return false
	}
	return now.Before(expiry)
}
