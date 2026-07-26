package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// The device authorization grant (RFC 8628) exists for inputs a browser
// cannot reach: a television, a CLI on a headless box, a device with no
// keyboard. The device shows a short code, the person types it on a phone,
// and the device polls until they approve.
//
// Two things make it different from the code flow, and both shape what
// follows. The user code is typed by a human, so it is short — which makes it
// the only guessable credential in SESAME, and the reason attempts are bounded
// and the lifetime is minutes rather than hours. And the device polls, so the
// token endpoint has to distinguish "not yet" from "no" without either
// becoming an oracle or inviting a hot loop.

const (
	// EventDeviceAuthorizationStarted records a validated device request.
	EventDeviceAuthorizationStarted = "oidc.device_authorization_started"
	// EventDeviceAuthorizationApproved records a person approving a device.
	EventDeviceAuthorizationApproved = "oidc.device_authorization_approved"
	// EventDeviceAuthorizationDenied records a refusal, an expiry, or a user
	// code exhausted by wrong guesses. Denial is durable so a device cannot
	// poll past it.
	EventDeviceAuthorizationDenied = "oidc.device_authorization_denied"
	// EventDeviceCodeRedeemed records the device exchanging its code for
	// tokens. Single use, so a replay fails across a restart.
	EventDeviceCodeRedeemed = "oidc.device_code_redeemed"

	// DeviceAuthorizationIDPrefix distinguishes public device identifiers.
	DeviceAuthorizationIDPrefix = "dev_"

	// GrantTypeDeviceCode is the token grant a polling device presents.
	GrantTypeDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

	// DeviceCodeLifetime bounds the whole flow. RFC 8628 suggests values in
	// the tens of minutes; SESAME is deliberately at the short end, because
	// the user code is guessable in a way nothing else here is and its
	// exposure window is the main defence.
	DeviceCodeLifetime = 10 * time.Minute

	// DevicePollInterval is the minimum gap between polls, in seconds. A
	// device that ignores it is told to slow down rather than refused: the
	// device is usually not the attacker, it is badly written.
	DevicePollInterval = 5

	// DeviceUserCodeAttempts bounds wrong guesses at the verification
	// endpoint before the authorization is denied outright. The user code is
	// short by necessity; this is what stops it being brute-forced.
	DeviceUserCodeAttempts = 5

	deviceCodeBytes    = 32
	deviceUserCodeSize = 8
)

// deviceUserCodeAlphabet omits every character a person can misread or
// mistype: no O or 0, no I, L or 1, no S or 5, no U (mistaken for V when
// handwritten). Twenty symbols over eight positions is about 34 bits, which
// is above RFC 8628's floor and still readable off a screen.
const deviceUserCodeAlphabet = "ABCDEFGHJKMNPQRTVWXY"

// Device authorization states.
const (
	DevicePending  = "pending"
	DeviceApproved = "approved"
	DeviceDenied   = "denied"
	DeviceRedeemed = "redeemed"
)

// DeviceAuthorization is one persisted device grant.
//
// Like an interaction, it never carries the device code itself — only a
// digest. The user code is different: it has to be looked up by the value a
// person types, so it is stored as given. That is safe only because it is
// short-lived, attempt-bounded, and useless without also approving it as an
// authenticated principal.
type DeviceAuthorization struct {
	ID       string   `json:"device_authorization_id"`
	TenantID string   `json:"tenant_id"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	UserCode string   `json:"user_code"`
	Status   string   `json:"status"`
	// AttemptsLeft counts down wrong user codes at the verification surface.
	AttemptsLeft int    `json:"attempts_left"`
	Interval     int    `json:"interval"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
	// PrincipalID and SessionID are set on approval and record who the
	// eventual tokens speak for.
	PrincipalID string `json:"principal_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	Assurance   string `json:"assurance,omitempty"`
	// CodeDigest is the device code's digest, cleared once the authorization
	// is spent — redeemed or denied — so nothing presentable remains.
	// SpentDigest keeps the value it had, which is what lets a replayed or
	// refused code be refused for its real reason rather than as an unknown
	// code.
	CodeDigest  string `json:"device_code_digest,omitempty"`
	SpentDigest string `json:"spent_device_code_digest,omitempty"`
	// DeniedReason is a stable code for the audit ledger, never returned to
	// the polling device.
	DeniedReason string `json:"denied_reason,omitempty"`
}

// DeviceAuthorizationStartedPayload is the versioned payload of
// EventDeviceAuthorizationStarted.
type DeviceAuthorizationStartedPayload struct {
	DeviceAuthorizationID string   `json:"device_authorization_id"`
	TenantID              string   `json:"tenant_id"`
	ClientID              string   `json:"client_id"`
	Scopes                []string `json:"scopes"`
	UserCode              string   `json:"user_code"`
	CodeDigest            string   `json:"device_code_digest"`
	Interval              int      `json:"interval"`
	AttemptsLeft          int      `json:"attempts_left"`
	CreatedAt             string   `json:"created_at"`
	ExpiresAt             string   `json:"expires_at"`
}

// DeviceAuthorizationApprovedPayload is the versioned payload of
// EventDeviceAuthorizationApproved.
type DeviceAuthorizationApprovedPayload struct {
	DeviceAuthorizationID string `json:"device_authorization_id"`
	TenantID              string `json:"tenant_id"`
	PrincipalID           string `json:"principal_id"`
	SessionID             string `json:"session_id"`
	Assurance             string `json:"assurance"`
	ApprovedAt            string `json:"approved_at"`
}

// DeviceAuthorizationDeniedPayload is the versioned payload of
// EventDeviceAuthorizationDenied.
type DeviceAuthorizationDeniedPayload struct {
	DeviceAuthorizationID string `json:"device_authorization_id"`
	TenantID              string `json:"tenant_id"`
	Reason                string `json:"reason"`
	DeniedAt              string `json:"denied_at"`
}

// DeviceCodeRedeemedPayload is the versioned payload of
// EventDeviceCodeRedeemed.
type DeviceCodeRedeemedPayload struct {
	DeviceAuthorizationID string `json:"device_authorization_id"`
	TenantID              string `json:"tenant_id"`
	RedeemedAt            string `json:"redeemed_at"`
}

// Stable denial reasons. They reach the audit ledger; the polling device is
// told only "access_denied".
const (
	DeviceDeniedByUser    = "denied_by_user"
	DeviceDeniedExpired   = "expired"
	DeviceDeniedExhausted = "user_code_attempts_exhausted"
)

// NewDeviceAuthorizationID returns a random device authorization identifier.
func NewDeviceAuthorizationID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate device authorization ID: %w", err)
	}
	return DeviceAuthorizationIDPrefix + hex.EncodeToString(value), nil
}

// ValidateDeviceAuthorizationID rejects values that cannot be one.
func ValidateDeviceAuthorizationID(id string) error {
	if !strings.HasPrefix(id, DeviceAuthorizationIDPrefix) ||
		len(id) != len(DeviceAuthorizationIDPrefix)+32 {
		return fmt.Errorf("device authorization ID must be %s followed by 32 hex characters",
			DeviceAuthorizationIDPrefix)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, DeviceAuthorizationIDPrefix)); err != nil {
		return fmt.Errorf("device authorization ID must be %s followed by 32 hex characters",
			DeviceAuthorizationIDPrefix)
	}
	return nil
}

// NewDeviceCode returns the device's own credential and the digest to store.
//
// It is a full-entropy secret because the device holds it in memory and never
// shows it to anyone — unlike the user code, which a person has to read and
// type.
func NewDeviceCode() (code string, digest string, err error) {
	return newBearerValue(deviceCodeBytes, "device code")
}

// NewUserCode returns the short code a person types.
//
// Drawn from a confusable-free alphabet with crypto/rand rather than a
// modulus over a byte, so every symbol is equally likely — a biased user code
// would shrink the search space that attempt-bounding is protecting.
func NewUserCode() (string, error) {
	limit := big.NewInt(int64(len(deviceUserCodeAlphabet)))
	var built strings.Builder
	for range deviceUserCodeSize {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("generate user code: %w", err)
		}
		built.WriteByte(deviceUserCodeAlphabet[index.Int64()])
	}
	// Grouped for reading aloud and typing; the separator is stripped on the
	// way back in.
	code := built.String()
	return code[:4] + "-" + code[4:], nil
}

// NormalizeUserCode makes a typed code comparable to a generated one.
//
// People type spaces, lower case, and either dash or none. Refusing those
// would be hostile without being safer: the value is compared against exactly
// one stored code, so normalising cannot widen what matches.
func NormalizeUserCode(typed string) string {
	symbols := userCodeSymbols(typed)
	if len(symbols) != deviceUserCodeSize {
		// Not a well-formed code; hand back what was found so a caller that
		// skipped validation cannot mistake it for a canonical value.
		return symbols
	}
	return symbols[:4] + "-" + symbols[4:]
}

// userCodeSymbols strips everything that is not part of the alphabet: case,
// spaces, and whichever separator the person used.
func userCodeSymbols(typed string) string {
	var built strings.Builder
	for _, character := range strings.ToUpper(typed) {
		if strings.ContainsRune(deviceUserCodeAlphabet, character) {
			built.WriteRune(character)
		}
	}
	return built.String()
}

// ValidateUserCode checks the shape of a typed code before it is looked up.
//
// It counts alphabet symbols rather than the length of the normalised string.
// Those differ: a nine-symbol code comes back undashed and is exactly as long
// as a valid eight-symbol code with its dash, so a length check on the
// formatted value accepts one code too many.
func ValidateUserCode(code string) error {
	if len(userCodeSymbols(code)) != deviceUserCodeSize {
		return fmt.Errorf("a user code is %d characters from the device's alphabet",
			deviceUserCodeSize)
	}
	return nil
}

// ValidateDeviceScopes bounds what a device may ask for.
func ValidateDeviceScopes(scopes []string) error {
	if len(scopes) > maxScopes {
		return fmt.Errorf("a device authorization must not request more than %d scopes",
			maxScopes)
	}
	return nil
}

// Pending reports whether the authorization is still waiting for a person and
// has not run out of time.
func (d DeviceAuthorization) Pending(now time.Time) bool {
	return d.Status == DevicePending && !d.Expired(now)
}

// Expired reports whether the whole flow has timed out. A malformed timestamp
// counts as expired: an authorization whose deadline cannot be read is not one
// to keep honouring.
func (d DeviceAuthorization) Expired(now time.Time) bool {
	deadline, err := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if err != nil {
		return true
	}
	return !now.Before(deadline)
}

// Approved reports whether a person has bound a session to the device and the
// device may still collect its tokens.
func (d DeviceAuthorization) Approved(now time.Time) bool {
	return d.Status == DeviceApproved && !d.Expired(now)
}
