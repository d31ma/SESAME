package federation

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
	// EventLoginStarted records a federated login leaving for the provider.
	EventLoginStarted = "federation.login_started"
	// EventLoginCompleted records a verified assertion becoming a session.
	EventLoginCompleted = "federation.login_completed"
	// EventLoginFailed records a rejected assertion, with a reason.
	EventLoginFailed = "federation.login_failed"
	// EventSubjectLinked records an external subject bound to a principal.
	EventSubjectLinked = "federation.subject_linked"
	// EventSubjectUnlinked records that binding being removed.
	EventSubjectUnlinked = "federation.subject_unlinked"

	// LoginIDPrefix distinguishes federated login transactions.
	LoginIDPrefix = "fed_"

	// LoginLifetime bounds how long a federated login may stay open. It is
	// generous enough for a person to authenticate at a provider, including
	// an MFA prompt, and short enough that an abandoned transaction is not a
	// standing replay target.
	LoginLifetime = 15 * time.Minute

	stateRandBytes    = 32
	nonceRandBytes    = 32
	verifierRandBytes = 32
)

// Login states. A transaction moves forward only.
const (
	LoginPending   = "pending"
	LoginCompleted = "completed"
	LoginFailed    = "failed"
)

var (
	// ErrLoginNotPending means the transaction was already spent. A federated
	// login is single-use: replaying a provider's authorization code against
	// a completed transaction must not mint a second session.
	ErrLoginNotPending = errors.New("this federated login is no longer pending")
	// ErrLoginExpired means the transaction outlived LoginLifetime.
	ErrLoginExpired = errors.New("this federated login has expired")
	// ErrStateMismatch means the callback did not come from the request
	// SESAME started, which is what state exists to detect.
	ErrStateMismatch = errors.New("the federated login state does not match")
)

// Login is one federated authentication attempt, persisted so it survives a
// restart between leaving for the provider and coming back.
//
// State, nonce, and the PKCE verifier are secrets: they are stored as digests
// or sealed, never in a form a ledger reader could replay. The identifier is
// not a secret and is safe to log.
type Login struct {
	ID         string `json:"login_id"`
	TenantID   string `json:"tenant_id"`
	ProviderID string `json:"provider_id"`
	Status     string `json:"status"`
	// StateDigest verifies the state parameter returned by the provider.
	StateDigest string `json:"state_digest"`
	// NonceDigest is not used for comparison — the nonce itself must be
	// compared against the ID token — so the plaintext nonce is sealed
	// alongside. This digest exists so a reader can correlate without
	// holding the secret.
	NonceDigest string `json:"nonce_digest"`
	// RedirectURI is where the provider was told to return the browser. It is
	// replayed at the token endpoint, where providers require it to match.
	RedirectURI string    `json:"redirect_uri"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// LoginStartedPayload is the versioned payload of EventLoginStarted.
type LoginStartedPayload struct {
	LoginID     string `json:"login_id"`
	TenantID    string `json:"tenant_id"`
	ProviderID  string `json:"provider_id"`
	StateDigest string `json:"state_digest"`
	NonceDigest string `json:"nonce_digest"`
	RedirectURI string `json:"redirect_uri"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	// SecretsSealed carries the state, nonce, and PKCE verifier under
	// AES-256-GCM. They must be recoverable to complete the exchange, so they
	// are encrypted rather than hashed.
	SecretsSealed string `json:"secrets_sealed"`
}

// LoginCompletedPayload is the versioned payload of EventLoginCompleted.
type LoginCompletedPayload struct {
	LoginID     string `json:"login_id"`
	TenantID    string `json:"tenant_id"`
	ProviderID  string `json:"provider_id"`
	PrincipalID string `json:"principal_id"`
	SubjectHash string `json:"subject_hash"`
	Provisioned bool   `json:"provisioned,omitempty"`
	CompletedAt string `json:"completed_at"`
}

// LoginFailedPayload is the versioned payload of EventLoginFailed. The reason
// is a stable code, never the assertion or any part of it.
type LoginFailedPayload struct {
	LoginID    string `json:"login_id"`
	TenantID   string `json:"tenant_id"`
	ProviderID string `json:"provider_id"`
	Reason     string `json:"reason"`
	FailedAt   string `json:"failed_at"`
}

// SubjectLinkedPayload is the versioned payload of EventSubjectLinked.
//
// SubjectHash rather than the subject itself: an external subject identifies
// a person at a provider, and the ledger is append-only. Storing the hash
// keeps the link checkable without making the ledger a directory of every
// federated user's provider identity.
type SubjectLinkedPayload struct {
	TenantID    string `json:"tenant_id"`
	ProviderID  string `json:"provider_id"`
	PrincipalID string `json:"principal_id"`
	SubjectHash string `json:"subject_hash"`
	LinkedAt    string `json:"linked_at"`
}

// SubjectUnlinkedPayload is the versioned payload of EventSubjectUnlinked.
type SubjectUnlinkedPayload struct {
	TenantID    string `json:"tenant_id"`
	ProviderID  string `json:"provider_id"`
	PrincipalID string `json:"principal_id"`
	SubjectHash string `json:"subject_hash"`
	Reason      string `json:"reason,omitempty"`
}

// NewLoginID returns a random federated login identifier.
//
// It is an identifier, not a secret: state carries the unguessable part.
func NewLoginID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate federated login identifier: %w", err)
	}
	return LoginIDPrefix + hex.EncodeToString(value), nil
}

// ValidateLoginID rejects values that cannot be login identifiers.
func ValidateLoginID(id string) error {
	if !strings.HasPrefix(id, LoginIDPrefix) || len(id) != len(LoginIDPrefix)+32 {
		return fmt.Errorf("login ID must be %s followed by 32 hex characters", LoginIDPrefix)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, LoginIDPrefix)); err != nil {
		return fmt.Errorf("login ID must be %s followed by 32 hex characters", LoginIDPrefix)
	}
	return nil
}

// NewSecret returns one high-entropy URL-safe value, used for state, nonce,
// and the PKCE verifier.
func NewSecret(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate federated login secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// NewState, NewNonce, and NewVerifier name the three secrets a federated
// login needs, so a caller cannot accidentally reuse one value for two jobs.
func NewState() (string, error)    { return NewSecret(stateRandBytes) }
func NewNonce() (string, error)    { return NewSecret(nonceRandBytes) }
func NewVerifier() (string, error) { return NewSecret(verifierRandBytes) }

// Digest is the stored form of a federated login secret.
func Digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// SubjectHash binds an external subject to its provider before hashing, so
// the same subject string at two providers is two different people.
//
// The provider identifier is length-prefixed rather than merely separated. A
// separator alone is ambiguous: with a plain delimiter, ("idp_a", "b\x00c")
// and ("idp_a\x00b", "c") hash identically, which would let one provider's
// subject collide with another's. Validated provider identifiers cannot
// currently contain the separator, but relying on a caller's validation to
// keep a hash injective is the kind of assumption that quietly stops holding.
func SubjectHash(providerID, subject string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s", len(providerID), providerID, subject)))
	return hex.EncodeToString(sum[:])
}

// Challenge derives the S256 code challenge from a verifier.
//
// PKCE is mandatory outbound as well as inbound. SESAME is a confidential
// client at the provider, so PKCE is not strictly required of it; sending it
// anyway costs nothing and removes code interception as a concern even when a
// provider's own redirect handling is weak.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// MatchState compares a returned state against the stored digest in constant
// time.
func MatchState(presented, storedDigest string) bool {
	return subtle.ConstantTimeCompare([]byte(Digest(presented)), []byte(storedDigest)) == 1
}

// Usable reports whether a login may still be completed.
//
// Expiry is checked before status so an expired-and-pending transaction reads
// as expired, which is the more useful diagnosis.
func (l Login) Usable(now time.Time) error {
	if !now.Before(l.ExpiresAt) {
		return ErrLoginExpired
	}
	if l.Status != LoginPending {
		return ErrLoginNotPending
	}
	return nil
}
