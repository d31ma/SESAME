package federation_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/domain/federation"
)

const (
	testIssuer   = "https://idp.example.com"
	testClientID = "sesame-at-the-provider"
	testNonce    = "nonce-for-this-login"
	testSubject  = "external-subject-1"
)

// provider is a stand-in OpenID Provider that can mint both honest and
// hostile ID tokens, so every rejection below is proven against a real
// signature rather than a hand-written string.
type provider struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

func newProvider(t *testing.T) *provider {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return &provider{rsaKey: rsaKey, ecKey: ecKey}
}

func (p *provider) keySet(t *testing.T) federation.KeySet {
	t.Helper()

	return federation.KeySet{Keys: []federation.JWK{
		{
			KeyType:  "RSA",
			KeyID:    "rsa-1",
			Modulus:  base64.RawURLEncoding.EncodeToString(p.rsaKey.N.Bytes()),
			Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.rsaKey.E)).Bytes()),
		},
		{
			KeyType: "EC",
			KeyID:   "ec-1",
			Curve:   "P-256",
			X:       base64.RawURLEncoding.EncodeToString(p.ecKey.X.Bytes()),
			Y:       base64.RawURLEncoding.EncodeToString(p.ecKey.Y.Bytes()),
		},
	}}
}

func claims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   testIssuer,
		"sub":   testSubject,
		"aud":   testClientID,
		"nonce": testNonce,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"email": "person@example.com",
	}
}

// sign produces a compact JWS. header overrides let a test forge exactly one
// thing at a time.
func (p *provider) sign(t *testing.T, header map[string]any, body map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(bodyJSON)
	sum := sha256.Sum256([]byte(signing))

	var signature []byte
	switch header["alg"] {
	case "RS256":
		signature, err = rsa.SignPKCS1v15(rand.Reader, p.rsaKey, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatalf("sign RS256: %v", err)
		}
	case "ES256":
		r, s, signErr := ecdsa.Sign(rand.Reader, p.ecKey, sum[:])
		if signErr != nil {
			t.Fatalf("sign ES256: %v", signErr)
		}
		signature = make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
	case "none":
		signature = nil
	default:
		// An algorithm SESAME should refuse before it ever reaches a key.
		signature = []byte("not-a-real-signature")
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifyIDTokenAcceptsHonestTokens(t *testing.T) {
	t.Parallel()

	idp := newProvider(t)
	keys := idp.keySet(t)

	for _, algorithm := range []struct{ alg, kid string }{
		{"RS256", "rsa-1"},
		{"ES256", "ec-1"},
	} {
		t.Run(algorithm.alg, func(t *testing.T) {
			t.Parallel()

			token := idp.sign(t,
				map[string]any{"alg": algorithm.alg, "kid": algorithm.kid, "typ": "JWT"},
				claims())
			assertion, err := federation.VerifyIDToken(
				token, keys, testIssuer, testClientID, testNonce, time.Now())
			if err != nil {
				t.Fatalf("VerifyIDToken() error = %v", err)
			}
			if assertion.Subject != testSubject {
				t.Fatalf("subject = %q, want %q", assertion.Subject, testSubject)
			}
			if assertion.Claims["email"] != "person@example.com" {
				t.Fatalf("the claim set did not survive verification: %#v", assertion.Claims)
			}
		})
	}
}

// TestVerifyIDTokenRefusesAlgorithmConfusion covers the family of attacks that
// try to choose their own verification scheme.
func TestVerifyIDTokenRefusesAlgorithmConfusion(t *testing.T) {
	t.Parallel()

	idp := newProvider(t)
	keys := idp.keySet(t)

	cases := []struct {
		name   string
		header map[string]any
		want   string
	}{
		{
			// The classic: strip the signature and declare it unnecessary.
			name:   "none",
			header: map[string]any{"alg": "none", "kid": "rsa-1"},
			want:   "allowlist",
		},
		{
			// HS256 with the RSA public key as the MAC secret. The key is
			// published, so accepting this would let anyone mint tokens.
			name:   "HS256",
			header: map[string]any{"alg": "HS256", "kid": "rsa-1"},
			want:   "allowlist",
		},
		{
			name:   "unknown algorithm",
			header: map[string]any{"alg": "PS999", "kid": "rsa-1"},
			want:   "allowlist",
		},
		{
			// An RSA algorithm pointed at an EC key: the token asks SESAME to
			// interpret one key type as another.
			name:   "key type mismatch",
			header: map[string]any{"alg": "RS256", "kid": "ec-1"},
			want:   "EC key but the token declares a RSA algorithm",
		},
		{
			name:   "unknown kid",
			header: map[string]any{"alg": "RS256", "kid": "attacker-key"},
			want:   "no key in the provider's key set",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token := idp.sign(t, testCase.header, claims())
			_, err := federation.VerifyIDToken(
				token, keys, testIssuer, testClientID, testNonce, time.Now())
			if err == nil {
				t.Fatal("VerifyIDToken accepted a token it must refuse")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}

// TestVerifyIDTokenRefusesForgedSignature proves the signature is actually
// checked rather than merely parsed.
func TestVerifyIDTokenRefusesForgedSignature(t *testing.T) {
	t.Parallel()

	idp := newProvider(t)
	other := newProvider(t)
	keys := idp.keySet(t)

	// Signed by a key the provider does not publish, but claiming a kid it
	// does. This is the shape of a compromised-but-not-rotated attack.
	token := other.sign(t, map[string]any{"alg": "RS256", "kid": "rsa-1"}, claims())
	_, err := federation.VerifyIDToken(token, keys, testIssuer, testClientID, testNonce, time.Now())
	if err == nil {
		t.Fatal("VerifyIDToken accepted a token signed by an unpublished key")
	}
	if !strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("error = %v, want an invalid-signature error", err)
	}
}

// TestVerifyIDTokenRefusesTamperedBody proves body changes invalidate the
// signature, which is what stops subject substitution.
func TestVerifyIDTokenRefusesTamperedBody(t *testing.T) {
	t.Parallel()

	idp := newProvider(t)
	keys := idp.keySet(t)

	token := idp.sign(t, map[string]any{"alg": "RS256", "kid": "rsa-1"}, claims())
	parts := strings.Split(token, ".")
	tampered := claims()
	tampered["sub"] = "somebody-else"
	swapped, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(swapped)

	_, err = federation.VerifyIDToken(
		strings.Join(parts, "."), keys, testIssuer, testClientID, testNonce, time.Now())
	if err == nil {
		t.Fatal("VerifyIDToken accepted a token whose subject was swapped")
	}
}

// TestVerifyIDTokenEnforcesClaims covers the checks that make a valid
// signature insufficient.
func TestVerifyIDTokenEnforcesClaims(t *testing.T) {
	t.Parallel()

	idp := newProvider(t)
	keys := idp.keySet(t)
	now := time.Now()

	cases := []struct {
		name   string
		mutate func(map[string]any)
		nonce  string
		when   time.Time
		want   string
	}{
		{
			name:   "wrong issuer",
			mutate: func(c map[string]any) { c["iss"] = "https://evil.example.com" },
			want:   "declares issuer",
		},
		{
			name:   "wrong audience",
			mutate: func(c map[string]any) { c["aud"] = "some-other-client" },
			want:   "addressed to",
		},
		{
			// A token minted for another relying party that happens to list
			// SESAME too. Without the azp check this replays here.
			name: "multiple audiences without azp",
			mutate: func(c map[string]any) {
				c["aud"] = []any{testClientID, "another-client"}
			},
			want: "azp is not this client",
		},
		{
			name: "multiple audiences with wrong azp",
			mutate: func(c map[string]any) {
				c["aud"] = []any{testClientID, "another-client"}
				c["azp"] = "another-client"
			},
			want: "azp is not this client",
		},
		{
			name:   "no subject",
			mutate: func(c map[string]any) { delete(c, "sub") },
			want:   "no subject",
		},
		{
			name:   "no expiry",
			mutate: func(c map[string]any) { delete(c, "exp") },
			want:   "no expiry",
		},
		{
			name:   "expired beyond skew",
			mutate: func(c map[string]any) { c["exp"] = now.Add(-2 * time.Minute).Unix() },
			want:   "expired",
		},
		{
			name:   "issued in the future",
			mutate: func(c map[string]any) { c["iat"] = now.Add(2 * time.Minute).Unix() },
			want:   "issued in the future",
		},
		{
			name:   "not yet valid",
			mutate: func(c map[string]any) { c["nbf"] = now.Add(2 * time.Minute).Unix() },
			want:   "not yet valid",
		},
		{
			// A token from a different login at the same provider.
			name:   "replayed from another login",
			mutate: func(c map[string]any) { c["nonce"] = "a-different-logins-nonce" },
			want:   "nonce",
		},
		{
			name:   "no nonce in the token",
			mutate: func(c map[string]any) { delete(c, "nonce") },
			want:   "nonce",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			body := claims()
			testCase.mutate(body)
			token := idp.sign(t, map[string]any{"alg": "RS256", "kid": "rsa-1"}, body)

			_, err := federation.VerifyIDToken(
				token, keys, testIssuer, testClientID, testNonce, now)
			if err == nil {
				t.Fatal("VerifyIDToken accepted a token it must refuse")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}

// TestVerifyIDTokenRefusesAMissingLoginNonce covers the fail-closed case: if
// SESAME has no nonce recorded, it must not accept a token that also has none.
func TestVerifyIDTokenRefusesAMissingLoginNonce(t *testing.T) {
	t.Parallel()

	idp := newProvider(t)
	keys := idp.keySet(t)

	body := claims()
	delete(body, "nonce")
	token := idp.sign(t, map[string]any{"alg": "RS256", "kid": "rsa-1"}, body)

	_, err := federation.VerifyIDToken(token, keys, testIssuer, testClientID, "", time.Now())
	if err == nil {
		t.Fatal("VerifyIDToken accepted a token when no nonce was recorded")
	}
}

// TestVerifyIDTokenRefusesWeakKeys covers the key-quality floor.
func TestVerifyIDTokenRefusesWeakKeys(t *testing.T) {
	t.Parallel()

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak key: %v", err)
	}
	idp := &provider{rsaKey: weak}
	keys := federation.KeySet{Keys: []federation.JWK{{
		KeyType:  "RSA",
		KeyID:    "rsa-1",
		Modulus:  base64.RawURLEncoding.EncodeToString(weak.N.Bytes()),
		Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(weak.E)).Bytes()),
	}}}

	token := idp.sign(t, map[string]any{"alg": "RS256", "kid": "rsa-1"}, claims())
	_, err = federation.VerifyIDToken(token, keys, testIssuer, testClientID, testNonce, time.Now())
	if err == nil {
		t.Fatal("VerifyIDToken accepted a 1024-bit RSA key")
	}
	if !strings.Contains(err.Error(), "2048") {
		t.Fatalf("error = %v, want it to name the minimum key size", err)
	}
}

// TestVerifyIDTokenRefusesOffCurvePoints covers a malformed EC key that would
// otherwise reach ecdsa.Verify.
func TestVerifyIDTokenRefusesOffCurvePoints(t *testing.T) {
	t.Parallel()

	idp := newProvider(t)
	keys := federation.KeySet{Keys: []federation.JWK{{
		KeyType: "EC",
		KeyID:   "ec-1",
		Curve:   "P-256",
		X:       base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
	}}}

	token := idp.sign(t, map[string]any{"alg": "ES256", "kid": "ec-1"}, claims())
	_, err := federation.VerifyIDToken(token, keys, testIssuer, testClientID, testNonce, time.Now())
	if err == nil {
		t.Fatal("VerifyIDToken accepted a point that is not on the curve")
	}
	if !strings.Contains(err.Error(), "not a point on its declared curve") {
		t.Fatalf("error = %v, want an off-curve rejection", err)
	}
}

// TestSelectKeyWithoutKid covers the one case where guessing is acceptable and
// the one where it is not.
func TestSelectKeyWithoutKid(t *testing.T) {
	t.Parallel()

	idp := newProvider(t)
	token := idp.sign(t, map[string]any{"alg": "RS256"}, claims())

	single := federation.KeySet{Keys: []federation.JWK{{
		KeyType:  "RSA",
		Modulus:  base64.RawURLEncoding.EncodeToString(idp.rsaKey.N.Bytes()),
		Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(idp.rsaKey.E)).Bytes()),
	}}}
	if _, err := federation.VerifyIDToken(
		token, single, testIssuer, testClientID, testNonce, time.Now()); err != nil {
		t.Fatalf("VerifyIDToken() with one unambiguous key error = %v", err)
	}

	// Two RSA keys and no kid: there is nothing to choose on, and choosing
	// would mean trying keys until one works.
	other := newProvider(t)
	several := federation.KeySet{Keys: []federation.JWK{
		single.Keys[0],
		{
			KeyType:  "RSA",
			Modulus:  base64.RawURLEncoding.EncodeToString(other.rsaKey.N.Bytes()),
			Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(other.rsaKey.E)).Bytes()),
		},
	}}
	_, err := federation.VerifyIDToken(
		token, several, testIssuer, testClientID, testNonce, time.Now())
	if err == nil {
		t.Fatal("VerifyIDToken guessed between several keys with no kid")
	}
}

// TestUnknownKeyIsDistinguishable matters operationally: the host's remedy for
// a rotated provider key is to re-fetch the JWKS, and it can only do that if
// this failure is told apart from a forgery.
func TestUnknownKeyIsDistinguishable(t *testing.T) {
	t.Parallel()

	idp := newProvider(t)
	token := idp.sign(t, map[string]any{"alg": "RS256", "kid": "rotated-away"}, claims())
	_, err := federation.VerifyIDToken(
		token, idp.keySet(t), testIssuer, testClientID, testNonce, time.Now())
	if !errors.Is(err, federation.ErrUnknownKey) {
		t.Fatalf("error = %v, want ErrUnknownKey", err)
	}
}
