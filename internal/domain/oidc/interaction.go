// External interaction and authorization codes.
//
// SESAME is headless: it owns no listener and renders no page. A browser-
// facing flow therefore runs as a persisted interaction that the host drives.
// The host receives an authorization request, hands it here for validation,
// authenticates the user with the ordinary session flow, and hands back proof
// of that session to obtain the authorization code.
//
// The interaction is what makes that handoff safe. It is a durable record
// bound to one client, one redirect URI, and one PKCE challenge, addressed by
// an unguessable handle whose secret half the host must present. Nothing in
// the round trip is taken on the host's word: the redirect URI the code is
// finally delivered to is the one validated here, not one supplied later.
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	// EventInteractionStarted records a validated authorization request.
	EventInteractionStarted = "oidc.interaction_started"
	// EventInteractionFailed records an interaction that can issue nothing.
	EventInteractionFailed = "oidc.interaction_failed"
	// EventCodeIssued records an authorization code bound to a principal.
	EventCodeIssued = "oidc.code_issued"
	// EventCodeRedeemed records a code being spent. A code is single-use, so
	// this event is what makes a second attempt fail after a restart.
	EventCodeRedeemed = "oidc.code_redeemed"

	// InteractionIDPrefix distinguishes public interaction identifiers.
	InteractionIDPrefix = "int_"

	// ResponseTypeCode is the only response type SESAME implements. The
	// implicit and hybrid flows return tokens through the front channel and
	// are not modelled.
	ResponseTypeCode = "code"

	// ChallengeMethodS256 is the only PKCE method SESAME accepts. "plain"
	// puts the verifier in the authorization request, which defeats the
	// point of the exchange.
	ChallengeMethodS256 = "S256"

	// GrantTypeAuthorizationCode is the only token grant SESAME implements.
	GrantTypeAuthorizationCode = "authorization_code"

	// InteractionLifetime bounds how long a user may take to authenticate.
	InteractionLifetime = 15 * time.Minute
	// CodeLifetime bounds an authorization code. It is deliberately short:
	// the code travels through a browser redirect, so its exposure window
	// should be measured against a back-channel round trip, not a session.
	CodeLifetime = 60 * time.Second

	minVerifierLength = 43
	maxVerifierLength = 128
	maxStateLength    = 512
	maxNonceLength    = 512

	interactionSecretBytes = 32
	codeBytes              = 32
)

// Interaction states.
const (
	InteractionAwaitingAuthentication = "awaiting_authentication"
	InteractionCompleted              = "completed"
	InteractionFailed                 = "failed"
)

// Interaction is one persisted browser-facing authorization request.
//
// It never carries the handle secret or the authorization code: only their
// digests are durable, exactly as for a session secret.
type Interaction struct {
	ID          string   `json:"interaction_id"`
	TenantID    string   `json:"tenant_id"`
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`
	State       string   `json:"state,omitempty"`
	Nonce       string   `json:"nonce,omitempty"`
	// CodeChallenge is the PKCE challenge the eventual token request must
	// produce a verifier for. It is not a secret: it is a hash.
	CodeChallenge string `json:"code_challenge"`
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
	ExpiresAt     string `json:"expires_at"`
	// PrincipalID and SessionID are set when the interaction completes and
	// record who the code speaks for.
	PrincipalID string `json:"principal_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	Assurance   string `json:"assurance,omitempty"`
	// SecretDigest and CodeDigest are omitted when cleared so a public
	// surface that strips them does not advertise the fields at all.
	SecretDigest string `json:"secret_digest,omitempty"`
	CodeDigest   string `json:"code_digest,omitempty"`
	CodeExpires  string `json:"code_expires_at,omitempty"`
	// CodeRedeemed marks a spent code. The interaction record is kept rather
	// than deleted so a replayed code is refused for a known reason instead
	// of an indistinguishable "not found".
	CodeRedeemed bool `json:"code_redeemed,omitempty"`
}

// InteractionStartedPayload is the versioned payload of
// EventInteractionStarted. Every field is a scalar or a flat array of
// scalars, per FYLO's document model.
type InteractionStartedPayload struct {
	InteractionID string   `json:"interaction_id"`
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	Scopes        []string `json:"scopes"`
	State         string   `json:"state,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	CodeChallenge string   `json:"code_challenge"`
	CreatedAt     string   `json:"created_at"`
	ExpiresAt     string   `json:"expires_at"`
	SecretDigest  string   `json:"secret_digest"`
}

// CodeIssuedPayload is the versioned payload of EventCodeIssued.
type CodeIssuedPayload struct {
	InteractionID string `json:"interaction_id"`
	TenantID      string `json:"tenant_id"`
	PrincipalID   string `json:"principal_id"`
	SessionID     string `json:"session_id"`
	Assurance     string `json:"assurance"`
	CodeDigest    string `json:"code_digest"`
	CodeExpiresAt string `json:"code_expires_at"`
}

// CodeRedeemedPayload is the versioned payload of EventCodeRedeemed.
type CodeRedeemedPayload struct {
	InteractionID string `json:"interaction_id"`
	TenantID      string `json:"tenant_id"`
}

// InteractionFailedPayload is the versioned payload of
// EventInteractionFailed.
type InteractionFailedPayload struct {
	InteractionID string `json:"interaction_id"`
	TenantID      string `json:"tenant_id"`
	Reason        string `json:"reason"`
}

// NewInteractionID returns a random public interaction identifier.
func NewInteractionID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate interaction ID: %w", err)
	}
	return InteractionIDPrefix + hex.EncodeToString(value), nil
}

// ValidateInteractionID rejects values that cannot be interaction
// identifiers.
func ValidateInteractionID(id string) error {
	if !strings.HasPrefix(id, InteractionIDPrefix) || len(id) != len(InteractionIDPrefix)+32 {
		return errors.New("interaction ID must be int_ followed by 32 hex characters")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, InteractionIDPrefix)); err != nil {
		return errors.New("interaction ID must be int_ followed by 32 hex characters")
	}
	return nil
}

// NewInteractionSecret returns a fresh handle secret and its digest.
func NewInteractionSecret() (secret string, digest string, err error) {
	return newBearerValue(interactionSecretBytes, "interaction secret")
}

// NewAuthorizationCode returns a fresh authorization code and its digest.
func NewAuthorizationCode() (code string, digest string, err error) {
	return newBearerValue(codeBytes, "authorization code")
}

func newBearerValue(size int, label string) (string, string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", "", fmt.Errorf("generate %s: %w", label, err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(value)
	return encoded, Digest(encoded), nil
}

// Digest hashes a bearer-equivalent value for storage and comparison.
//
// SHA-256 without a password-hashing construction is deliberate, for the same
// reason as a session secret: the value is 256 bits of uniform randomness, so
// there is no guessable input space to slow an attacker through.
func Digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// VerifyDigest compares a presented value against a stored digest in constant
// time.
func VerifyDigest(storedDigest, presented string) bool {
	if storedDigest == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(Digest(presented)), []byte(storedDigest)) == 1
}

// ValidateResponseType accepts only advertised response types.
//
// This and the two validators below read the same lists the discovery
// document publishes, so what is advertised and what is accepted cannot
// drift apart.
func ValidateResponseType(responseType string) error {
	if !slices.Contains(SupportedResponseTypes, responseType) {
		return fmt.Errorf("response_type must be one of %s", strings.Join(SupportedResponseTypes, ", "))
	}
	return nil
}

// ValidateGrantType accepts only advertised grants. The implicit and
// resource-owner-password grants are not modelled at all.
func ValidateGrantType(grantType string) error {
	if !slices.Contains(SupportedGrantTypes, grantType) {
		return fmt.Errorf("grant_type must be one of %s", strings.Join(SupportedGrantTypes, ", "))
	}
	return nil
}

// ValidateCodeChallenge enforces a well-formed S256 PKCE challenge.
//
// PKCE is required of every client, not only public ones. A confidential
// client's secret does not protect the code while it sits in a redirect, and
// requiring the exchange unconditionally removes a per-client decision that
// could be got wrong.
func ValidateCodeChallenge(challenge, method string) error {
	if !slices.Contains(SupportedChallengeMethods, method) {
		return fmt.Errorf("code_challenge_method must be one of %s",
			strings.Join(SupportedChallengeMethods, ", "))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("code_challenge must be the base64url-encoded SHA-256 of the verifier, without padding")
	}
	return nil
}

// ValidateCodeVerifier enforces the RFC 7636 verifier shape.
func ValidateCodeVerifier(verifier string) error {
	if len(verifier) < minVerifierLength || len(verifier) > maxVerifierLength {
		return fmt.Errorf("code_verifier must be between %d and %d characters", minVerifierLength, maxVerifierLength)
	}
	for _, character := range verifier {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-' || character == '.' || character == '_' || character == '~':
		default:
			return fmt.Errorf("code_verifier contains unsupported character %q", character)
		}
	}
	return nil
}

// VerifyCodeVerifier reports whether a verifier produces the stored
// challenge. The comparison is constant time, though the challenge is not
// itself secret, because the verifier is.
func VerifyCodeVerifier(challenge, verifier string) bool {
	if ValidateCodeVerifier(verifier) != nil {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// ValidateState enforces a bounded, printable state parameter. State is the
// client's CSRF token; SESAME stores and returns it unchanged.
func ValidateState(state string) error { return boundedOpaque(state, maxStateLength, "state") }

// ValidateNonce enforces a bounded, printable nonce, which binds an ID token
// to the authorization request that asked for it.
func ValidateNonce(nonce string) error { return boundedOpaque(nonce, maxNonceLength, "nonce") }

func boundedOpaque(value string, limit int, label string) error {
	if value == "" {
		return nil
	}
	if len(value) > limit {
		return fmt.Errorf("%s must not exceed %d bytes", label, limit)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%s must not contain control characters", label)
		}
	}
	return nil
}

// Pending reports whether an interaction may still be completed.
func (i Interaction) Pending(now time.Time) bool {
	return i.Status == InteractionAwaitingAuthentication && !expired(i.ExpiresAt, now)
}

// CodeUsable reports whether the issued code may still be redeemed. A spent,
// expired, or unparseable-expiry code is not usable: a code whose bound
// cannot be read is not a code with no bound.
func (i Interaction) CodeUsable(now time.Time) bool {
	if i.Status != InteractionCompleted || i.CodeRedeemed || i.CodeDigest == "" {
		return false
	}
	return !expired(i.CodeExpires, now)
}

func expired(timestamp string, now time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return true
	}
	return !now.Before(parsed)
}
