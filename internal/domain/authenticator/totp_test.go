package authenticator

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// rfc6238Secret is the seed from RFC 6238 Appendix B: the ASCII string
// "12345678901234567890" in base32.
var rfc6238Secret = base32.StdEncoding.WithPadding(base32.NoPadding).
	EncodeToString([]byte("12345678901234567890"))

// TestTOTPMatchesRFC6238Vectors checks the SHA-1 vectors from RFC 6238
// Appendix B, truncated to the six digits SESAME issues. Passing these is
// what makes an ordinary authenticator app interoperate.
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	t.Parallel()

	vectors := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for unix, want := range vectors {
		counter := TOTPCounter(time.Unix(unix, 0).UTC())
		got, err := TOTPCode(rfc6238Secret, counter)
		if err != nil {
			t.Fatalf("TOTPCode(%d) error = %v", unix, err)
		}
		if got != want {
			t.Fatalf("TOTPCode at %d = %s, want %s", unix, got, want)
		}
	}
}

func TestTOTPSecretGeneration(t *testing.T) {
	t.Parallel()

	first, err := NewTOTPSecret()
	if err != nil || ValidateTOTPSecret(first) != nil {
		t.Fatalf("NewTOTPSecret() = %q, %v", first, err)
	}
	second, _ := NewTOTPSecret()
	if first == second {
		t.Fatal("NewTOTPSecret() returned the same value twice")
	}
	for _, secret := range []string{"", "not base32!", "AAAA"} {
		if err := ValidateTOTPSecret(secret); err == nil {
			t.Fatalf("ValidateTOTPSecret(%q) accepted an invalid secret", secret)
		}
	}
}

func TestVerifyTOTPCodeWindowAndReplay(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	current := TOTPCounter(now)
	code, err := TOTPCode(rfc6238Secret, current)
	if err != nil {
		t.Fatalf("TOTPCode() error = %v", err)
	}

	matched, counter, err := VerifyTOTPCode(rfc6238Secret, code, now, 0)
	if err != nil || !matched || counter != current {
		t.Fatalf("VerifyTOTPCode(current) = %t, %d, %v", matched, counter, err)
	}

	// The drift window accepts one step either side.
	for _, offset := range []int64{-1, 1} {
		drifted, codeErr := TOTPCode(rfc6238Secret, current+offset)
		if codeErr != nil {
			t.Fatalf("TOTPCode(offset %d) error = %v", offset, codeErr)
		}
		matched, counter, err = VerifyTOTPCode(rfc6238Secret, drifted, now, 0)
		if err != nil || !matched || counter != current+offset {
			t.Fatalf("drift %d = %t, %d, %v", offset, matched, counter, err)
		}
	}

	// Two steps out is outside the window.
	distant, _ := TOTPCode(rfc6238Secret, current+2)
	if matched, _, _ = VerifyTOTPCode(rfc6238Secret, distant, now, 0); matched {
		t.Fatal("a code two steps away was accepted")
	}

	// Replay: the same code fails once its counter is spent, even though it
	// is still inside its own validity window.
	if matched, _, _ = VerifyTOTPCode(rfc6238Secret, code, now, current); matched {
		t.Fatal("a spent code was accepted again")
	}
	// An earlier still-valid code is likewise refused after a later one.
	previous, _ := TOTPCode(rfc6238Secret, current-1)
	if matched, _, _ = VerifyTOTPCode(rfc6238Secret, previous, now, current); matched {
		t.Fatal("an earlier code was accepted after a later one")
	}
	// A later code in the window still works.
	next, _ := TOTPCode(rfc6238Secret, current+1)
	matched, counter, err = VerifyTOTPCode(rfc6238Secret, next, now, current)
	if err != nil || !matched || counter != current+1 {
		t.Fatalf("next-step code after spend = %t, %d, %v", matched, counter, err)
	}
}

func TestVerifyTOTPCodeRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	for name, code := range map[string]string{
		"empty":      "",
		"short":      "12345",
		"long":       "1234567",
		"nondigit":   "12345a",
		"whitespace": "12345 ",
	} {
		matched, _, err := VerifyTOTPCode(rfc6238Secret, code, now, 0)
		if err != nil || matched {
			t.Fatalf("VerifyTOTPCode(%s) = %t, %v", name, matched, err)
		}
	}
	// A malformed secret is an operational error, not a wrong code.
	if _, _, err := VerifyTOTPCode("not base32!", "123456", now, 0); err == nil {
		t.Fatal("VerifyTOTPCode accepted a malformed secret")
	}
}

func TestProvisioningURI(t *testing.T) {
	t.Parallel()

	uri := TOTPProvisioningURI("SESAME", "alice@example.com", rfc6238Secret)
	for _, want := range []string{
		"otpauth://totp/",
		"secret=" + rfc6238Secret,
		"issuer=SESAME",
		"digits=6",
		"period=30",
		"algorithm=SHA1",
	} {
		if !strings.Contains(uri, want) {
			t.Fatalf("provisioning URI %q does not contain %q", uri, want)
		}
	}
}

func TestSealedSecretsRoundTripAndFailClosed(t *testing.T) {
	t.Parallel()

	key := make([]byte, SealedSecretKeyBytes)
	for index := range key {
		key[index] = byte(index)
	}
	secret := rfc6238Secret

	sealed, err := Seal(key, secret)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if strings.Contains(sealed, secret) {
		t.Fatal("the sealed value contains the plaintext secret")
	}
	opened, err := Open(key, sealed)
	if err != nil || opened != secret {
		t.Fatalf("Open() = %q, %v", opened, err)
	}

	// Two seals of one secret differ because the nonce is fresh.
	again, _ := Seal(key, secret)
	if again == sealed {
		t.Fatal("two seals of one secret are identical; the nonce is not random")
	}

	// A wrong key fails rather than returning a plausible secret.
	wrong := make([]byte, SealedSecretKeyBytes)
	if _, err := Open(wrong, sealed); err == nil {
		t.Fatal("Open() accepted a wrong key")
	}

	// Tampering with any part fails authentication.
	for name, tampered := range map[string]string{
		"flipped ciphertext": sealed[:len(sealed)-2] + "AA",
		"missing prefix":     strings.TrimPrefix(sealed, sealedPrefix),
		"truncated":          sealed[:len(sealed)/2],
		"empty":              "",
	} {
		if _, err := Open(key, tampered); err == nil {
			t.Fatalf("Open(%s) accepted a tampered value", name)
		}
	}

	// Without a key the facility refuses rather than storing in the clear.
	if _, err := Seal(nil, secret); err == nil {
		t.Fatal("Seal() accepted an absent key")
	}
	if _, err := Seal(make([]byte, 8), secret); err == nil {
		t.Fatal("Seal() accepted a short key")
	}
}
