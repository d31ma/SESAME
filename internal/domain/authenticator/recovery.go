package authenticator

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Recovery codes are the way back in when the second-factor device is gone.
// Without them, losing a phone means an operator has to disable MFA by hand,
// which is both a support burden and the weakest link an attacker will aim
// at.
const (
	// KindRecoveryCode is a single-use backup factor.
	KindRecoveryCode = "recovery_code"

	// EventRecoveryCodesIssued records a freshly generated set, replacing
	// any previous one.
	EventRecoveryCodesIssued = "authenticator.recovery_codes_issued"
	// EventRecoveryCodeUsed records one code being spent.
	EventRecoveryCodeUsed = "authenticator.recovery_code_used"

	// RecoveryCodeCount is how many codes an issue produces.
	RecoveryCodeCount = 10

	recoveryCodeBytes  = 10
	recoveryCodeGroups = 4
)

// RecoveryCodeSet is returned once, at issue. The plaintext codes exist only
// here; afterwards only their digests are durable.
type RecoveryCodeSet struct {
	Codes []string `json:"codes"`
}

// RecoveryCodesIssuedPayload is the versioned payload of an issue event. It
// carries digests, never the codes.
type RecoveryCodesIssuedPayload struct {
	PrincipalID string   `json:"principal_id"`
	TenantID    string   `json:"tenant_id"`
	Digests     []string `json:"digests"`
}

// RecoveryCodeUsedPayload records one spent code by its digest, which is
// what makes reuse detectable after a restart.
type RecoveryCodeUsedPayload struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
	Digest      string `json:"digest"`
}

// NewRecoveryCodes generates a fresh set and their digests. The two slices
// are index-aligned.
func NewRecoveryCodes() (codes []string, digests []string, err error) {
	codes = make([]string, 0, RecoveryCodeCount)
	digests = make([]string, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		value := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(value); err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		// Grouped hex is readable enough to write down and retype, which is
		// the situation these exist for.
		raw := hex.EncodeToString(value)
		grouped := make([]string, 0, recoveryCodeGroups)
		size := len(raw) / recoveryCodeGroups
		for group := range recoveryCodeGroups {
			grouped = append(grouped, raw[group*size:(group+1)*size])
		}
		code := strings.Join(grouped, "-")
		codes = append(codes, code)
		digests = append(digests, RecoveryCodeDigest(code))
	}
	return codes, digests, nil
}

// NormalizeRecoveryCode makes retyping forgiving without weakening the code:
// case and separators carry no entropy.
func NormalizeRecoveryCode(code string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(strings.TrimSpace(code)) {
		if character == '-' || character == ' ' {
			continue
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

// RecoveryCodeDigest hashes a code for storage and comparison.
//
// SHA-256 without a password-hashing construction is deliberate: a code is 80
// bits of uniform randomness, so there is no guessable input space to slow an
// attacker through.
func RecoveryCodeDigest(code string) string {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

// MatchRecoveryCode finds the digest a presented code satisfies, comparing
// every candidate in constant time so a match does not reveal its position.
func MatchRecoveryCode(digests []string, code string) (string, bool) {
	if strings.TrimSpace(code) == "" {
		return "", false
	}
	presented := RecoveryCodeDigest(code)
	matched := ""
	for _, digest := range digests {
		if subtle.ConstantTimeCompare([]byte(presented), []byte(digest)) == 1 {
			matched = digest
		}
	}
	return matched, matched != ""
}

// ValidateRecoveryDigests rejects a malformed stored set.
func ValidateRecoveryDigests(digests []string) error {
	if len(digests) == 0 {
		return errors.New("a recovery code set must not be empty")
	}
	seen := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if len(digest) != sha256.Size*2 {
			return errors.New("recovery code digest must be a SHA-256 hex digest")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return errors.New("recovery code digest must be a SHA-256 hex digest")
		}
		if _, duplicate := seen[digest]; duplicate {
			return errors.New("recovery code set contains a duplicate")
		}
		seen[digest] = struct{}{}
	}
	return nil
}
