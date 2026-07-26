// Refresh tokens as rotating families.
//
// A refresh token is long-lived and travels to a client that may be a phone,
// a laptop, or a container image — so the interesting question is not how to
// keep one safe, but how to notice when one has been copied.
//
// Every use rotates: the presented token is spent and a successor is issued
// in the same family. A legitimate client always holds the newest token, so
// presenting a spent one means two parties hold tokens from one family, and
// exactly one of them is a thief. SESAME cannot tell which, so it revokes the
// whole family. The user re-authenticates; the thief gets nothing.
package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// EventRefreshIssued records a refresh token entering a family. The
	// first one also brings the family into existence.
	EventRefreshIssued = "oidc.refresh_issued"
	// EventRefreshSpent records a refresh token being exchanged. Spending is
	// what makes a later presentation of the same token detectable.
	EventRefreshSpent = "oidc.refresh_spent"
	// EventRefreshFamilyRevoked records a durable, replay-safe kill of every
	// token descended from one authorization — on reuse detection, on
	// logout, or by an operator.
	EventRefreshFamilyRevoked = "oidc.refresh_family_revoked"

	// RefreshIDPrefix and RefreshFamilyIDPrefix distinguish public
	// identifiers.
	RefreshIDPrefix       = "rft_"
	RefreshFamilyIDPrefix = "rfm_"

	// GrantTypeRefreshToken exchanges a refresh token for a new token set.
	GrantTypeRefreshToken = "refresh_token"

	// RefreshLifetime bounds one refresh token. A client that goes quiet for
	// longer must send the user back through authentication.
	RefreshLifetime = 30 * 24 * time.Hour
	// RefreshFamilyLifetime is the absolute bound on a family. Rotation
	// alone would let a chain live forever; this is the ceiling that stops
	// one authorization from becoming a permanent grant.
	RefreshFamilyLifetime = 90 * 24 * time.Hour

	refreshSecretBytes = 32
)

// Reasons recorded on a family revocation.
const (
	RevokedReasonReuse  = "refresh_token_reuse_detected"
	RevokedReasonLogout = "logout"
)

// RefreshToken is one token in a rotating family. It never carries the token
// value: only its digest is durable.
type RefreshToken struct {
	ID          string   `json:"refresh_token_id"`
	FamilyID    string   `json:"family_id"`
	TenantID    string   `json:"tenant_id"`
	ClientID    string   `json:"client_id"`
	PrincipalID string   `json:"principal_id"`
	SessionID   string   `json:"session_id"`
	Scopes      []string `json:"scopes"`
	Assurance   string   `json:"assurance,omitempty"`
	IssuedAt    string   `json:"issued_at"`
	ExpiresAt   string   `json:"expires_at"`
	// Thumbprint is the DPoP key this token is bound to (RFC 9449 section 7).
	// It travels down the family: a rotation that dropped it would let a
	// stolen refresh token be exchanged for an unbound bearer token, which
	// would make the binding a formality anyone could shed.
	Thumbprint string `json:"dpop_thumbprint,omitempty"`
	// SecretDigest is omitted when cleared so a public surface that strips
	// it does not advertise the field at all.
	SecretDigest string `json:"secret_digest,omitempty"`
	Spent        bool   `json:"spent,omitempty"`
}

// RefreshFamily is every token descended from one authorization. Revoking it
// is the unit of "this grant is over".
type RefreshFamily struct {
	ID        string `json:"family_id"`
	TenantID  string `json:"tenant_id"`
	ClientID  string `json:"client_id"`
	SessionID string `json:"session_id"`
	StartedAt string `json:"started_at"`
	ExpiresAt string `json:"expires_at"`
	Revoked   bool   `json:"revoked,omitempty"`
	Reason    string `json:"revoked_reason,omitempty"`
}

// RefreshIssuedPayload is the versioned payload of EventRefreshIssued. Every
// field is a scalar or a flat array of scalars, per FYLO's document model.
type RefreshIssuedPayload struct {
	RefreshTokenID string   `json:"refresh_token_id"`
	FamilyID       string   `json:"family_id"`
	TenantID       string   `json:"tenant_id"`
	ClientID       string   `json:"client_id"`
	PrincipalID    string   `json:"principal_id"`
	SessionID      string   `json:"session_id"`
	Scopes         []string `json:"scopes"`
	Assurance      string   `json:"assurance,omitempty"`
	IssuedAt       string   `json:"issued_at"`
	ExpiresAt      string   `json:"expires_at"`
	Thumbprint     string   `json:"dpop_thumbprint,omitempty"`
	SecretDigest   string   `json:"secret_digest"`
	// FamilyExpiresAt is set only on the event that starts a family, so a
	// rotation cannot quietly extend the absolute ceiling.
	FamilyExpiresAt string `json:"family_expires_at,omitempty"`
}

// RefreshSpentPayload is the versioned payload of EventRefreshSpent.
type RefreshSpentPayload struct {
	RefreshTokenID string `json:"refresh_token_id"`
	FamilyID       string `json:"family_id"`
	TenantID       string `json:"tenant_id"`
}

// RefreshFamilyRevokedPayload is the versioned payload of
// EventRefreshFamilyRevoked.
type RefreshFamilyRevokedPayload struct {
	FamilyID string `json:"family_id"`
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

// NewRefreshID returns a random public refresh-token identifier.
func NewRefreshID() (string, error) { return newPrefixedID(RefreshIDPrefix, "refresh token") }

// NewRefreshFamilyID returns a random public family identifier.
func NewRefreshFamilyID() (string, error) {
	return newPrefixedID(RefreshFamilyIDPrefix, "refresh family")
}

func newPrefixedID(prefix, label string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate %s ID: %w", label, err)
	}
	return prefix + hex.EncodeToString(value), nil
}

// ValidateRefreshID rejects values that cannot be refresh-token identifiers.
func ValidateRefreshID(id string) error {
	if !strings.HasPrefix(id, RefreshIDPrefix) || len(id) != len(RefreshIDPrefix)+32 {
		return errors.New("refresh token ID must be rft_ followed by 32 hex characters")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, RefreshIDPrefix)); err != nil {
		return errors.New("refresh token ID must be rft_ followed by 32 hex characters")
	}
	return nil
}

// ValidateRefreshFamilyID rejects values that cannot be family identifiers.
func ValidateRefreshFamilyID(id string) error {
	if !strings.HasPrefix(id, RefreshFamilyIDPrefix) || len(id) != len(RefreshFamilyIDPrefix)+32 {
		return errors.New("refresh family ID must be rfm_ followed by 32 hex characters")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, RefreshFamilyIDPrefix)); err != nil {
		return errors.New("refresh family ID must be rfm_ followed by 32 hex characters")
	}
	return nil
}

// NewRefreshSecret returns a fresh refresh-token secret and its digest.
func NewRefreshSecret() (secret string, digest string, err error) {
	return newBearerValue(refreshSecretBytes, "refresh token secret")
}

// Usable reports whether a refresh token may still be exchanged. Spent,
// expired, and unreadable-expiry all deny.
func (r RefreshToken) Usable(now time.Time) bool {
	return !r.Spent && !expired(r.ExpiresAt, now)
}

// Live reports whether a family may still issue successors.
func (f RefreshFamily) Live(now time.Time) bool {
	return !f.Revoked && !expired(f.ExpiresAt, now)
}

// NarrowScopes resolves a refresh request's scope parameter against what the
// family already holds.
//
// An empty request keeps the granted set. Anything else must be a subset:
// a refresh token is a way to keep an existing grant alive, never a way to
// acquire access the user was not asked about.
func NarrowScopes(granted, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return granted, nil
	}
	held := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		held[scope] = struct{}{}
	}
	narrowed := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		if err := ValidateScope(scope); err != nil {
			return nil, err
		}
		if _, ok := held[scope]; !ok {
			return nil, fmt.Errorf("scope %q was not granted", scope)
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		narrowed = append(narrowed, scope)
	}
	return narrowed, nil
}

// GrantsOfflineAccess reports whether a scope set makes a client eligible for
// a refresh token.
func GrantsOfflineAccess(scopes []string) bool {
	for _, scope := range scopes {
		if scope == ScopeOfflineAccess {
			return true
		}
	}
	return false
}
