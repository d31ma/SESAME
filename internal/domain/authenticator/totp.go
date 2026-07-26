package authenticator

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP as specified by RFC 6238.
//
// HMAC-SHA1 is the algorithm every authenticator app implements, and RFC 6238
// still specifies it. SHA-1's collision weaknesses do not apply to HMAC, and
// choosing an algorithm nothing can enrol would be worse security than one
// whose weakness is irrelevant here.
const (
	// KindTOTP is a time-based one-time password authenticator.
	KindTOTP = "totp"

	// EventTOTPEnrolled records an enrolled but not yet usable authenticator.
	EventTOTPEnrolled = "authenticator.totp_enrolled"
	// EventTOTPActivated records the enrollment being proven and made usable.
	EventTOTPActivated = "authenticator.totp_activated"
	// EventTOTPUsed records the counter consumed by a successful code, which
	// is what makes replay detectable.
	EventTOTPUsed = "authenticator.totp_used"

	// TOTPDigits is the code length every authenticator app expects.
	TOTPDigits = 6
	// TOTPPeriodSeconds is the time step.
	TOTPPeriodSeconds = 30
	// TOTPDriftSteps accepts one step either side of now, tolerating about
	// 30 seconds of clock skew in each direction. Widening this multiplies
	// the codes valid at any instant, so it stays at the RFC's suggestion.
	TOTPDriftSteps = 1

	totpSecretBytes = 20
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// TOTPEnrollment is returned once, at enrollment. The secret is shown to its
// owner exactly here; afterwards only the sealed form is durable.
type TOTPEnrollment struct {
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
}

// TOTPEnrolledPayload is the versioned payload of an EventTOTPEnrolled event.
// It carries the sealed secret, never the plaintext.
type TOTPEnrolledPayload struct {
	PrincipalID  string `json:"principal_id"`
	TenantID     string `json:"tenant_id"`
	SealedSecret string `json:"sealed_secret"`
}

// TOTPActivatedPayload is the versioned payload of an EventTOTPActivated
// event.
type TOTPActivatedPayload struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	Counter     int64  `json:"counter"`
}

// TOTPUsedPayload records the time-step counter a successful code consumed.
type TOTPUsedPayload struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	Counter     int64  `json:"counter"`
}

// NewTOTPSecret returns a fresh base32 shared secret.
func NewTOTPSecret() (string, error) {
	value := make([]byte, totpSecretBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return totpEncoding.EncodeToString(value), nil
}

// ValidateTOTPSecret rejects secrets SESAME will not accept.
func ValidateTOTPSecret(secret string) error {
	decoded, err := totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return errors.New("TOTP secret must be unpadded base32")
	}
	if len(decoded) < 16 {
		return errors.New("TOTP secret must be at least 128 bits")
	}
	return nil
}

// TOTPProvisioningURI builds the otpauth URI an authenticator app scans.
//
// The issuer and account label are shown to the person enrolling, so the
// account uses their identifier. The URI carries the secret and is therefore
// as sensitive as the secret itself.
func TOTPProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprintf("%d", TOTPDigits))
	query.Set("period", fmt.Sprintf("%d", TOTPPeriodSeconds))
	return "otpauth://totp/" + label + "?" + query.Encode()
}

// TOTPCounter returns the time-step counter for an instant.
func TOTPCounter(now time.Time) int64 {
	return now.UTC().Unix() / TOTPPeriodSeconds
}

// TOTPCode computes the code for one counter.
func TOTPCode(secret string, counter int64) (string, error) {
	decoded, err := totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", errors.New("TOTP secret must be unpadded base32")
	}
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, uint64(counter))

	mac := hmac.New(sha1.New, decoded)
	mac.Write(message)
	sum := mac.Sum(nil)

	// RFC 4226 dynamic truncation.
	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	modulus := uint32(1)
	for range TOTPDigits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", TOTPDigits, truncated%modulus), nil
}

// VerifyTOTPCode checks a code against the secret within the drift window and
// returns the counter it consumed.
//
// lastCounter is the highest counter already spent by this authenticator.
// Codes at or below it are rejected even when otherwise valid, so a code
// observed in transit cannot be replayed during the rest of its own window.
// The comparison is constant-time.
func VerifyTOTPCode(
	secret string,
	code string,
	now time.Time,
	lastCounter int64,
) (matched bool, counter int64, err error) {
	if err := ValidateTOTPSecret(secret); err != nil {
		return false, 0, err
	}
	if len(code) != TOTPDigits {
		return false, 0, nil
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return false, 0, nil
		}
	}

	current := TOTPCounter(now)
	// Every candidate in the window is evaluated rather than returning on
	// the first hit, so acceptance time does not reveal which step matched.
	found := false
	accepted := int64(0)
	for offset := -TOTPDriftSteps; offset <= TOTPDriftSteps; offset++ {
		candidate := current + int64(offset)
		expected, codeErr := TOTPCode(secret, candidate)
		if codeErr != nil {
			return false, 0, codeErr
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			found = true
			accepted = candidate
		}
	}
	if !found {
		return false, 0, nil
	}
	if accepted <= lastCounter {
		// A correct but already-spent code. Reporting this as a mismatch
		// keeps the caller from learning that the code was ever valid.
		return false, 0, nil
	}
	return true, accepted, nil
}
