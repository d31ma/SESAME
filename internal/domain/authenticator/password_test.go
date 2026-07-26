package authenticator

import (
	"strings"
	"testing"
)

const testPassword = "correct horse battery staple"

func TestPasswordVerifierRoundTrip(t *testing.T) {
	t.Parallel()

	verifier, err := NewPasswordVerifier(testPassword)
	if err != nil {
		t.Fatalf("NewPasswordVerifier() error = %v", err)
	}
	if !strings.HasPrefix(verifier, "$argon2id$") {
		t.Fatalf("verifier = %q, want a PHC string", verifier)
	}
	// The verifier must never contain the password in any encoding.
	if strings.Contains(verifier, testPassword) {
		t.Fatal("verifier contains the plaintext password")
	}

	matched, needsUpgrade, err := VerifyPassword(verifier, testPassword)
	if err != nil || !matched || needsUpgrade {
		t.Fatalf("VerifyPassword(correct) = %t, %t, %v", matched, needsUpgrade, err)
	}
	matched, _, err = VerifyPassword(verifier, testPassword+"x")
	if err != nil || matched {
		t.Fatalf("VerifyPassword(wrong) = %t, %v", matched, err)
	}

	// Two verifiers for the same password differ because the salt is fresh.
	other, err := NewPasswordVerifier(testPassword)
	if err != nil {
		t.Fatalf("NewPasswordVerifier() error = %v", err)
	}
	if other == verifier {
		t.Fatal("two verifiers for one password are identical; the salt is not random")
	}
}

func TestPasswordValidation(t *testing.T) {
	t.Parallel()

	if err := ValidatePassword(testPassword); err != nil {
		t.Fatalf("ValidatePassword(valid) error = %v", err)
	}
	for name, password := range map[string]string{
		"too short": "short",
		"empty":     "",
		"too long":  strings.Repeat("a", MaxPasswordLength+1),
	} {
		if err := ValidatePassword(password); err == nil {
			t.Fatalf("ValidatePassword(%s) accepted an invalid password", name)
		}
		if _, err := NewPasswordVerifier(password); err == nil {
			t.Fatalf("NewPasswordVerifier(%s) accepted an invalid password", name)
		}
	}
}

func TestVerifierParameterUpgradePath(t *testing.T) {
	t.Parallel()

	weaker := Parameters{Memory: 16 * 1024, Iterations: 1, Parallelism: 1}
	salt := make([]byte, saltBytes)
	for index := range salt {
		salt[index] = byte(index)
	}
	legacy := encode(weaker, salt, derive(testPassword, salt, weaker))

	matched, needsUpgrade, err := VerifyPassword(legacy, testPassword)
	if err != nil || !matched {
		t.Fatalf("VerifyPassword(legacy) = %t, %v", matched, err)
	}
	if !needsUpgrade {
		t.Fatal("a verifier below the current cost was not flagged for upgrade")
	}

	// Rehashing at current cost clears the flag.
	upgraded, err := NewPasswordVerifier(testPassword)
	if err != nil {
		t.Fatalf("NewPasswordVerifier() error = %v", err)
	}
	if _, needsUpgrade, err = VerifyPassword(upgraded, testPassword); err != nil || needsUpgrade {
		t.Fatalf("VerifyPassword(upgraded) needsUpgrade = %t, %v", needsUpgrade, err)
	}
}

func TestMalformedVerifiersFailClosed(t *testing.T) {
	t.Parallel()

	valid, err := NewPasswordVerifier(testPassword)
	if err != nil {
		t.Fatalf("NewPasswordVerifier() error = %v", err)
	}
	fields := strings.Split(valid, "$")

	malformed := map[string]string{
		"empty":              "",
		"not PHC":            "hunter2",
		"wrong algorithm":    strings.Replace(valid, "argon2id", "argon2i", 1),
		"missing version":    "$argon2id$m=65536,t=1,p=4$" + fields[4] + "$" + fields[5],
		"future version":     strings.Replace(valid, "v=19", "v=99", 1),
		"bad parameters":     "$argon2id$v=19$m=x,t=1,p=4$" + fields[4] + "$" + fields[5],
		"weak parameters":    "$argon2id$v=19$m=1,t=1,p=1$" + fields[4] + "$" + fields[5],
		"bad salt encoding":  "$argon2id$v=19$m=65536,t=1,p=4$!!!$" + fields[5],
		"truncated key":      "$argon2id$v=19$m=65536,t=1,p=4$" + fields[4] + "$AAAA",
		"trailing separator": valid + "$",
	}
	for name, verifier := range malformed {
		matched, _, err := VerifyPassword(verifier, testPassword)
		if err == nil {
			t.Fatalf("VerifyPassword(%s) accepted a malformed verifier", name)
		}
		if matched {
			t.Fatalf("VerifyPassword(%s) matched a malformed verifier", name)
		}
	}
}

func TestParametersAtLeast(t *testing.T) {
	t.Parallel()

	if !CurrentParameters.AtLeast(CurrentParameters) {
		t.Fatal("parameters are not at least themselves")
	}
	weaker := Parameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}
	if weaker.AtLeast(CurrentParameters) {
		t.Fatal("weaker parameters claimed to meet the current cost")
	}
	if !CurrentParameters.AtLeast(weaker) {
		t.Fatal("current parameters did not meet a weaker cost")
	}
	// A verifier stronger in one dimension and weaker in another does not
	// meet the bar: every dimension must hold.
	mixed := Parameters{
		Memory:      CurrentParameters.Memory * 2,
		Iterations:  CurrentParameters.Iterations,
		Parallelism: 1,
	}
	if CurrentParameters.Parallelism > 1 && mixed.AtLeast(CurrentParameters) {
		t.Fatal("mixed parameters claimed to meet the current cost")
	}
}
