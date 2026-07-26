package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const goodVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ-._~"

func TestPKCEIsS256Only(t *testing.T) {
	t.Parallel()

	challenge := challengeFor(goodVerifier)
	if err := ValidateCodeChallenge(challenge, ChallengeMethodS256); err != nil {
		t.Fatalf("ValidateCodeChallenge() = %v", err)
	}
	// "plain" carries the verifier in the authorization request, which
	// defeats the exchange; downgrading to it must not be possible.
	for _, method := range []string{"plain", "", "s256", "S512"} {
		if err := ValidateCodeChallenge(challenge, method); err == nil {
			t.Fatalf("ValidateCodeChallenge accepted method %q", method)
		}
	}
	// A challenge that is not a 32-byte base64url digest is refused, so a
	// caller cannot register a challenge it can trivially produce.
	for _, bad := range []string{"", "short", challenge + "=", strings.Repeat("A", 43) + "!"} {
		if err := ValidateCodeChallenge(bad, ChallengeMethodS256); err == nil {
			t.Fatalf("ValidateCodeChallenge accepted challenge %q", bad)
		}
	}
}

func TestVerifyCodeVerifier(t *testing.T) {
	t.Parallel()

	challenge := challengeFor(goodVerifier)
	if !VerifyCodeVerifier(challenge, goodVerifier) {
		t.Fatal("VerifyCodeVerifier rejected the matching verifier")
	}
	for name, verifier := range map[string]string{
		"empty":       "",
		"wrong":       strings.Repeat("b", 50),
		"too short":   strings.Repeat("a", minVerifierLength-1),
		"too long":    strings.Repeat("a", maxVerifierLength+1),
		"bad charset": strings.Repeat("a", 42) + "/",
		// The challenge itself is not a verifier, even though it hashes to
		// something well formed.
		"the challenge": challenge,
	} {
		if VerifyCodeVerifier(challenge, verifier) {
			t.Fatalf("VerifyCodeVerifier accepted the %s verifier", name)
		}
	}
}

func TestResponseAndGrantTypesAreFixed(t *testing.T) {
	t.Parallel()

	if err := ValidateResponseType(ResponseTypeCode); err != nil {
		t.Fatalf("ValidateResponseType(code) = %v", err)
	}
	// Implicit and hybrid return tokens through the front channel.
	for _, responseType := range []string{"", "token", "id_token", "code id_token", "code token"} {
		if err := ValidateResponseType(responseType); err == nil {
			t.Fatalf("ValidateResponseType accepted %q", responseType)
		}
	}
	for _, grant := range []string{
		GrantTypeAuthorizationCode, GrantTypeRefreshToken, GrantTypeDeviceCode,
	} {
		if err := ValidateGrantType(grant); err != nil {
			t.Fatalf("ValidateGrantType(%q) = %v", grant, err)
		}
	}
	// The two that are absent by design, not by omission. The password grant
	// hands a credential to every client; client_credentials authenticates no
	// person at all, so nothing here could speak for one.
	for _, grant := range []string{"", "password", "implicit", "client_credentials"} {
		if err := ValidateGrantType(grant); err == nil {
			t.Fatalf("ValidateGrantType accepted %q", grant)
		}
	}
	// Advertised and accepted are the same list, so discovery cannot promise a
	// grant the validator refuses.
	if len(SupportedGrantTypes) != 3 {
		t.Fatalf("SupportedGrantTypes = %v; adding one is a deliberate change to "+
			"what discovery advertises", SupportedGrantTypes)
	}
}

func TestBearerValuesAreDigestedNotStored(t *testing.T) {
	t.Parallel()

	secret, digest, err := NewInteractionSecret()
	if err != nil {
		t.Fatalf("NewInteractionSecret() error = %v", err)
	}
	if secret == digest || len(digest) != sha256.Size*2 {
		t.Fatalf("secret %q and digest %q", secret, digest)
	}
	if !VerifyDigest(digest, secret) {
		t.Fatal("VerifyDigest rejected the matching secret")
	}
	if VerifyDigest(digest, secret+"x") || VerifyDigest("", secret) {
		t.Fatal("VerifyDigest accepted a wrong or absent value")
	}

	code, codeDigest, err := NewAuthorizationCode()
	if err != nil {
		t.Fatalf("NewAuthorizationCode() error = %v", err)
	}
	if code == secret || codeDigest == digest {
		t.Fatal("two generated bearer values collided")
	}

	id, err := NewInteractionID()
	if err != nil {
		t.Fatalf("NewInteractionID() error = %v", err)
	}
	if err := ValidateInteractionID(id); err != nil {
		t.Fatalf("ValidateInteractionID(%q) = %v", id, err)
	}
	// The ID is a handle, not a credential: it must not be derivable from,
	// or usable as, the secret.
	if Digest(secret) == id || VerifyDigest(digest, id) {
		t.Fatal("the interaction ID is entangled with its secret")
	}
	for _, bad := range []string{"", "int_", "ses_" + strings.Repeat("0", 32)} {
		if err := ValidateInteractionID(bad); err == nil {
			t.Fatalf("ValidateInteractionID accepted %q", bad)
		}
	}
}

func TestInteractionAndCodeExpiry(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	interaction := Interaction{
		Status:    InteractionAwaitingAuthentication,
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	if !interaction.Pending(now) {
		t.Fatal("a fresh interaction is not pending")
	}
	if interaction.Pending(now.Add(2 * time.Minute)) {
		t.Fatal("an expired interaction is still pending")
	}
	// An unparseable expiry denies rather than meaning "no bound".
	unbounded := Interaction{Status: InteractionAwaitingAuthentication, ExpiresAt: "soon"}
	if unbounded.Pending(now) {
		t.Fatal("an interaction with an unreadable expiry is pending")
	}

	completed := Interaction{
		Status:      InteractionCompleted,
		CodeDigest:  "digest",
		CodeExpires: now.Add(CodeLifetime).Format(time.RFC3339Nano),
	}
	if !completed.CodeUsable(now) {
		t.Fatal("a fresh code is not usable")
	}
	if completed.CodeUsable(now.Add(2 * CodeLifetime)) {
		t.Fatal("an expired code is usable")
	}
	spent := completed
	spent.CodeRedeemed = true
	if spent.CodeUsable(now) {
		t.Fatal("a spent code is usable")
	}
	// A pending interaction has no code to redeem.
	if interaction.CodeUsable(now) {
		t.Fatal("a pending interaction offered a usable code")
	}
}

func TestStateAndNonceAreBoundedOpaque(t *testing.T) {
	t.Parallel()

	// Both are optional and pass through unchanged when present.
	for _, validate := range []func(string) error{ValidateState, ValidateNonce} {
		if err := validate(""); err != nil {
			t.Fatalf("an absent value was rejected: %v", err)
		}
		if err := validate("xyz-123_~."); err != nil {
			t.Fatalf("a printable value was rejected: %v", err)
		}
		if err := validate("bad\nvalue"); err == nil {
			t.Fatal("a control character was accepted")
		}
		if err := validate(strings.Repeat("a", maxStateLength+1)); err == nil {
			t.Fatal("an unbounded value was accepted")
		}
	}
}
