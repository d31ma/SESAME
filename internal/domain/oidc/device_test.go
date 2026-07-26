package oidc

import (
	"strings"
	"testing"
)

// TestUserCodeAlphabetExcludesConfusableCharacters: the user code is read off
// a screen and typed on a phone. A code containing O and 0, or I and 1, turns
// every mistyped character into a wasted attempt against a bounded budget.
func TestUserCodeAlphabetExcludesConfusableCharacters(t *testing.T) {
	t.Parallel()

	for _, confusable := range []rune{'0', 'O', '1', 'I', 'L', '5', 'S', 'U'} {
		if strings.ContainsRune(deviceUserCodeAlphabet, confusable) {
			t.Errorf("the user code alphabet contains %q, which is misread or mistyped", confusable)
		}
	}
	// Duplicates would silently bias the distribution.
	seen := map[rune]bool{}
	for _, character := range deviceUserCodeAlphabet {
		if seen[character] {
			t.Errorf("the alphabet repeats %q", character)
		}
		seen[character] = true
	}
}

// TestNewUserCodeIsUnbiasedAndUnguessable. Eight symbols over twenty is about
// 34 bits, above RFC 8628's floor — but only if every symbol is equally
// likely. The tempting implementation, a modulus over a random byte, is not:
// 256 does not divide by 20, so the first sixteen symbols come up about 8%
// more often and the real search space is smaller than the arithmetic says.
//
// Eight percent is invisible to an eyeballed range check, so this uses a
// chi-square goodness-of-fit test sized to separate that bias from natural
// variance. With 19 degrees of freedom, a uniform generator exceeds 52 about
// once in ten thousand runs, while the modulus version lands near 98.
func TestNewUserCodeIsUnbiasedAndUnguessable(t *testing.T) {
	t.Parallel()

	const (
		samples       = 12500
		chiSquareMax  = 52.0
		degreesOfFree = 19
	)

	counts := map[rune]int{}
	seen := map[string]bool{}
	for range samples {
		code, err := NewUserCode()
		if err != nil {
			t.Fatalf("NewUserCode() error = %v", err)
		}
		if err := ValidateUserCode(code); err != nil {
			t.Fatalf("NewUserCode produced %q, which ValidateUserCode rejects: %v", code, err)
		}
		if seen[code] {
			t.Fatalf("NewUserCode repeated %q within %d samples", code, samples)
		}
		seen[code] = true
		for _, character := range strings.ReplaceAll(code, "-", "") {
			counts[character]++
		}
	}

	draws := samples * deviceUserCodeSize
	expected := float64(draws) / float64(len(deviceUserCodeAlphabet))
	chiSquare := 0.0
	for _, character := range deviceUserCodeAlphabet {
		count, ok := counts[character]
		if !ok {
			t.Fatalf("symbol %q never appeared in %d draws; the generator "+
				"cannot reach part of its own alphabet", character, draws)
		}
		difference := float64(count) - expected
		chiSquare += difference * difference / expected
	}
	if chiSquare > chiSquareMax {
		t.Fatalf("user code symbols are not uniform: chi-square %.1f over %d "+
			"degrees of freedom exceeds %.0f — check for a modulus bias",
			chiSquare, degreesOfFree, chiSquareMax)
	}
	t.Logf("chi-square %.1f over %d draws (uniform passes below %.0f)",
		chiSquare, draws, chiSquareMax)
}

// TestNormalizeUserCodeAcceptsWhatPeopleType: refusing lower case or a missing
// dash would be hostile without being safer, because the value is compared
// against exactly one stored code.
func TestNormalizeUserCodeAcceptsWhatPeopleType(t *testing.T) {
	t.Parallel()

	canonical := "ABCD-EFGH"
	for name, typed := range map[string]string{
		"canonical":      "ABCD-EFGH",
		"lower case":     "abcd-efgh",
		"no separator":   "ABCDEFGH",
		"spaces":         "ABCD EFGH",
		"mixed and busy": " aBcD - eFgH ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := NormalizeUserCode(typed); got != canonical {
				t.Fatalf("NormalizeUserCode(%q) = %q, want %q", typed, got, canonical)
			}
		})
	}
}

// TestValidateUserCodeRefusesTheWrongShape. Normalisation must not become a
// way to smuggle a short or long code past the lookup.
func TestValidateUserCodeRefusesTheWrongShape(t *testing.T) {
	t.Parallel()

	for name, code := range map[string]string{
		"empty":            "",
		"too short":        "ABCD-EFG",
		"too long":         "ABCD-EFGHJ",
		"all separators":   "--------",
		"outside alphabet": "0000-1111",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateUserCode(code); err == nil {
				t.Fatalf("ValidateUserCode(%q) accepted it", code)
			}
		})
	}
}

// TestNewDeviceCodeIsAFullEntropySecret: unlike the user code, the device
// holds this one in memory and never shows it, so it has no reason to be
// short — and it is stored only as a digest.
func TestNewDeviceCodeIsAFullEntropySecret(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for range 256 {
		code, digest, err := NewDeviceCode()
		if err != nil {
			t.Fatalf("NewDeviceCode() error = %v", err)
		}
		if len(code) < 40 {
			t.Fatalf("device code %q is too short to be unguessable", code)
		}
		if code == digest {
			t.Fatal("the device code and its digest are the same value")
		}
		if digest != Digest(code) {
			t.Fatal("the returned digest is not the digest of the returned code")
		}
		if seen[code] {
			t.Fatalf("NewDeviceCode repeated %q", code)
		}
		seen[code] = true
	}
}

func TestValidateDeviceAuthorizationID(t *testing.T) {
	t.Parallel()

	id, err := NewDeviceAuthorizationID()
	if err != nil {
		t.Fatalf("NewDeviceAuthorizationID() error = %v", err)
	}
	if err := ValidateDeviceAuthorizationID(id); err != nil {
		t.Fatalf("ValidateDeviceAuthorizationID(%q) error = %v", id, err)
	}
	for name, value := range map[string]string{
		"empty":          "",
		"wrong prefix":   "int_" + strings.Repeat("a", 32),
		"short":          DeviceAuthorizationIDPrefix + "abcd",
		"not hex":        DeviceAuthorizationIDPrefix + strings.Repeat("z", 32),
		"an interaction": "int_" + strings.Repeat("a", 32),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateDeviceAuthorizationID(value); err == nil {
				t.Fatalf("ValidateDeviceAuthorizationID(%q) accepted it", value)
			}
		})
	}
}
