package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testClaims(now time.Time) Claims {
	return Claims{
		Issuer:    "https://sesame.example",
		Subject:   "prn_00000000000000000000000000000001",
		Audience:  "cli_test",
		ExpiresAt: now.Add(5 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ID:        "tok_1",
		Extra:     map[string]any{"scope": "openid profile"},
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	compact, err := key.Sign(testClaims(now))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	claims, body, err := key.Verify(compact, "https://sesame.example", "cli_test", now)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Subject != "prn_00000000000000000000000000000001" || body["scope"] != "openid profile" {
		t.Fatalf("claims = %#v, body = %#v", claims, body)
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	t.Parallel()

	key, _ := NewSigningKey()
	other, _ := NewSigningKey()
	now := time.Unix(1_700_000_000, 0).UTC()
	compact, err := key.Sign(testClaims(now))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	segments := strings.Split(compact, ".")

	// A token signed by another key is refused even though it is well formed.
	if _, _, err := other.Verify(compact, "https://sesame.example", "cli_test", now); err == nil {
		t.Fatal("Verify() accepted a token signed by a different key")
	}

	// The classic JWT failure: a header claiming a different algorithm must
	// not change how the token is verified.
	for name, header := range map[string]map[string]string{
		"none":      {"alg": "none", "typ": "JWT", "kid": key.ID},
		"symmetric": {"alg": "HS256", "typ": "JWT", "kid": key.ID},
		"other kid": {"alg": AlgorithmES256, "typ": "JWT", "kid": "someone-else"},
	} {
		encoded, _ := json.Marshal(header)
		forged := base64.RawURLEncoding.EncodeToString(encoded) + "." + segments[1] + "." + segments[2]
		if _, _, err := key.Verify(forged, "https://sesame.example", "cli_test", now); err == nil {
			t.Fatalf("Verify() accepted a %s header", name)
		}
	}

	// Tampering with the payload breaks the signature.
	tampered := segments[0] + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://sesame.example","sub":"prn_evil","exp":99999999999}`)) +
		"." + segments[2]
	if _, _, err := key.Verify(tampered, "https://sesame.example", "cli_test", now); err == nil {
		t.Fatal("Verify() accepted a tampered payload")
	}

	// Issuer, audience, and expiry are all enforced.
	if _, _, err := key.Verify(compact, "https://elsewhere.example", "cli_test", now); err == nil {
		t.Fatal("Verify() accepted a wrong issuer")
	}
	if _, _, err := key.Verify(compact, "https://sesame.example", "cli_other", now); err == nil {
		t.Fatal("Verify() accepted a wrong audience")
	}
	expired := now.Add(10 * time.Minute)
	if _, _, err := key.Verify(compact, "https://sesame.example", "cli_test", expired); err == nil {
		t.Fatal("Verify() accepted an expired token")
	}
	// Modest skew is tolerated so a slightly fast verifier does not reject
	// every fresh token.
	justExpired := time.Unix(testClaims(now).ExpiresAt, 0).Add(MaxClockSkew / 2)
	if _, _, err := key.Verify(compact, "https://sesame.example", "cli_test", justExpired); err != nil {
		t.Fatalf("Verify() rejected a token inside the skew window: %v", err)
	}

	for name, malformed := range map[string]string{
		"empty":         "",
		"two segments":  segments[0] + "." + segments[1],
		"bad signature": segments[0] + "." + segments[1] + ".AAAA",
	} {
		if _, _, err := key.Verify(malformed, "https://sesame.example", "cli_test", now); err == nil {
			t.Fatalf("Verify() accepted a %s token", name)
		}
	}
}

func TestReservedClaimsCannotBeShadowed(t *testing.T) {
	t.Parallel()

	key, _ := NewSigningKey()
	now := time.Unix(1_700_000_000, 0).UTC()
	claims := testClaims(now)
	claims.Extra = map[string]any{"sub": "prn_evil"}
	if _, err := key.Sign(claims); err == nil {
		t.Fatal("Sign() allowed an extra claim to shadow a registered one")
	}
}

func TestPublishedJWKCarriesNoPrivateMaterial(t *testing.T) {
	t.Parallel()

	key, _ := NewSigningKey()
	jwk := key.PublicJWK()
	if jwk.KeyID != key.ID || jwk.Curve != CurveP256 || jwk.Algorithm != AlgorithmES256 {
		t.Fatalf("PublicJWK() = %#v", jwk)
	}
	encoded, err := json.Marshal(JWKS{Keys: []JWK{jwk}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	// "d" is the private scalar; its presence would publish the key.
	var parsed map[string]any
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if strings.Contains(string(encoded), `"d"`) {
		t.Fatalf("published JWKS contains private material: %s", encoded)
	}

	// The coordinates are fixed width, which some verifiers require.
	for _, coordinate := range []string{jwk.X, jwk.Y} {
		raw, err := base64.RawURLEncoding.DecodeString(coordinate)
		if err != nil || len(raw) != coordinateBytes {
			t.Fatalf("coordinate %q decodes to %d bytes", coordinate, len(raw))
		}
	}
}

func TestSigningKeyEncodingRoundTrip(t *testing.T) {
	t.Parallel()

	key, _ := NewSigningKey()
	encoded, err := EncodeSigningKey(key)
	if err != nil {
		t.Fatalf("EncodeSigningKey() error = %v", err)
	}
	parsed, err := ParseSigningKey(encoded)
	if err != nil {
		t.Fatalf("ParseSigningKey() error = %v", err)
	}
	if parsed.ID != key.ID {
		t.Fatalf("round-tripped key ID = %q, want %q", parsed.ID, key.ID)
	}
	// A token signed before the round trip still verifies after it.
	now := time.Unix(1_700_000_000, 0).UTC()
	compact, _ := key.Sign(testClaims(now))
	if _, _, err := parsed.Verify(compact, "https://sesame.example", "cli_test", now); err != nil {
		t.Fatalf("round-tripped key could not verify: %v", err)
	}

	for name, bad := range map[string]string{
		"empty":     "",
		"not PEM":   "hunter2",
		"wrong PEM": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		if _, err := ParseSigningKey([]byte(bad)); err == nil {
			t.Fatalf("ParseSigningKey accepted %s", name)
		}
	}
}
