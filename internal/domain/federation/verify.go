package federation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

// MaxClockSkew tolerates modest disagreement between the provider's clock and
// this host's. It matches the value SESAME uses for its own tokens.
const MaxClockSkew = 60 * time.Second

// maxAssertionBytes bounds a compact JWT. Real ID tokens are a couple of
// kilobytes; anything approaching this is an attempt to make parsing
// expensive rather than a credential.
const maxAssertionBytes = 16 * 1024

var (
	// ErrUnknownKey means the provider signed with a key absent from the JWKS
	// SESAME holds. The host's remedy is to re-fetch the key set, which is
	// how provider key rotation is driven.
	ErrUnknownKey = errors.New("no key in the provider's key set matches the token's kid")
	// ErrAssertionExpired distinguishes a stale token from a forged one so
	// the caller can say something useful.
	ErrAssertionExpired = errors.New("the provider's ID token has expired")
	// ErrNonceMismatch means the token does not belong to this login attempt.
	ErrNonceMismatch = errors.New("the ID token nonce does not match this login")
)

// algorithm describes one accepted signature algorithm.
//
// SESAME signs only with ES256. Verifying an assertion someone else produced
// is a different question: providers overwhelmingly use RS256, and refusing
// it would mean refusing federation. The allowlist is explicit and closed —
// `none` and every HMAC algorithm are absent, so an attacker cannot downgrade
// into a mode where the verification key is the public key itself.
type algorithm struct {
	keyType string
	curve   elliptic.Curve
	hash    crypto.Hash
	newHash func() hash.Hash
}

var verificationAlgorithms = map[string]algorithm{
	"RS256": {keyType: "RSA", hash: crypto.SHA256, newHash: sha256.New},
	"RS384": {keyType: "RSA", hash: crypto.SHA384, newHash: sha512.New384},
	"RS512": {keyType: "RSA", hash: crypto.SHA512, newHash: sha512.New},
	"ES256": {keyType: "EC", curve: elliptic.P256(), hash: crypto.SHA256, newHash: sha256.New},
	"ES384": {keyType: "EC", curve: elliptic.P384(), hash: crypto.SHA384, newHash: sha512.New384},
	"ES512": {keyType: "EC", curve: elliptic.P521(), hash: crypto.SHA512, newHash: sha512.New},
}

// SupportedAlgorithms lists what SESAME will verify, for documentation and
// for the discovery-time compatibility check.
func SupportedAlgorithms() []string {
	return []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512"}
}

// JWK is one key from a provider's key set.
type JWK struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid,omitempty"`
	Use       string `json:"use,omitempty"`
	Algorithm string `json:"alg,omitempty"`
	Curve     string `json:"crv,omitempty"`
	// RSA
	Modulus  string `json:"n,omitempty"`
	Exponent string `json:"e,omitempty"`
	// EC
	X string `json:"x,omitempty"`
	Y string `json:"y,omitempty"`
}

// KeySet is a provider's published verification keys.
type KeySet struct {
	Keys []JWK `json:"keys"`
}

// ParseKeySet validates a fetched JWKS document.
func ParseKeySet(document []byte) (KeySet, error) {
	if len(document) == 0 {
		return KeySet{}, errors.New("the key set is empty")
	}
	if len(document) > MaxDocumentBytes {
		return KeySet{}, ErrDocumentTooLarge
	}
	var keys KeySet
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	if err := decoder.Decode(&keys); err != nil {
		return KeySet{}, fmt.Errorf("the key set is not valid JSON: %w", err)
	}
	if decoder.More() {
		return KeySet{}, errors.New("the key set contains trailing data")
	}
	if len(keys.Keys) == 0 {
		return KeySet{}, errors.New("the key set contains no keys")
	}
	if len(keys.Keys) > MaxJWKSKeys {
		return KeySet{}, fmt.Errorf("the key set declares more than %d keys", MaxJWKSKeys)
	}
	// Duplicate key IDs make selection ambiguous, and an ambiguous choice
	// between a real key and an attacker's is not one to make silently.
	seen := make(map[string]struct{}, len(keys.Keys))
	for _, key := range keys.Keys {
		if key.KeyID == "" {
			continue
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return KeySet{}, fmt.Errorf("the key set declares kid %q more than once", key.KeyID)
		}
		seen[key.KeyID] = struct{}{}
	}
	return keys, nil
}

// Assertion is what SESAME extracts from a verified ID token.
type Assertion struct {
	Issuer    string
	Subject   string
	Audience  string
	Nonce     string
	IssuedAt  int64
	ExpiresAt int64
	// Claims is the full verified claim set, for claim mapping. It is only
	// ever read through the provider's configured claim names.
	Claims map[string]any
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid,omitempty"`
	Type      string `json:"typ,omitempty"`
}

// VerifyIDToken checks a provider's ID token against its key set and the
// expectations of this login attempt.
//
// The order matters: the signature is verified before any claim is trusted,
// and the algorithm is pinned from the allowlist before a key is selected, so
// a forged header cannot choose its own verification scheme.
func VerifyIDToken(
	compact string,
	keys KeySet,
	issuer, clientID, nonce string,
	now time.Time,
) (Assertion, error) {
	if compact == "" {
		return Assertion{}, errors.New("the ID token is empty")
	}
	if len(compact) > maxAssertionBytes {
		return Assertion{}, errors.New("the ID token exceeds the maximum size")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return Assertion{}, errors.New("the ID token is not a compact JWS")
	}

	var header jwtHeader
	if err := decodeSegment(parts[0], &header); err != nil {
		return Assertion{}, fmt.Errorf("the ID token header is unreadable: %w", err)
	}
	spec, allowed := verificationAlgorithms[header.Algorithm]
	if !allowed {
		return Assertion{}, fmt.Errorf(
			"the ID token is signed with %q, which is not in SESAME's allowlist (%s)",
			header.Algorithm, strings.Join(SupportedAlgorithms(), ", "))
	}

	key, err := selectKey(keys, header.KeyID, spec.keyType)
	if err != nil {
		return Assertion{}, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Assertion{}, fmt.Errorf("the ID token signature is not base64url: %w", err)
	}
	signed := parts[0] + "." + parts[1]
	if err := verifySignature(spec, key, []byte(signed), signature); err != nil {
		return Assertion{}, err
	}

	// Only now is the body worth reading.
	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return Assertion{}, fmt.Errorf("the ID token body is unreadable: %w", err)
	}

	assertion := Assertion{
		Issuer:    stringClaim(claims, "iss"),
		Subject:   stringClaim(claims, "sub"),
		Nonce:     stringClaim(claims, "nonce"),
		IssuedAt:  intClaim(claims, "iat"),
		ExpiresAt: intClaim(claims, "exp"),
		Claims:    claims,
	}

	if assertion.Issuer != issuer {
		return Assertion{}, fmt.Errorf(
			"the ID token declares issuer %q, but %q is registered", assertion.Issuer, issuer)
	}
	if assertion.Subject == "" {
		return Assertion{}, errors.New("the ID token carries no subject")
	}
	audience, err := matchAudience(claims, clientID)
	if err != nil {
		return Assertion{}, err
	}
	assertion.Audience = audience

	if assertion.ExpiresAt == 0 {
		return Assertion{}, errors.New("the ID token carries no expiry")
	}
	if now.After(time.Unix(assertion.ExpiresAt, 0).Add(MaxClockSkew)) {
		return Assertion{}, ErrAssertionExpired
	}
	// A token issued in the future is either a clock problem or a forgery,
	// and accepting one extends its usable life past the provider's intent.
	if assertion.IssuedAt != 0 &&
		now.Add(MaxClockSkew).Before(time.Unix(assertion.IssuedAt, 0)) {
		return Assertion{}, errors.New("the ID token was issued in the future")
	}
	if notBefore := intClaim(claims, "nbf"); notBefore != 0 &&
		now.Add(MaxClockSkew).Before(time.Unix(notBefore, 0)) {
		return Assertion{}, errors.New("the ID token is not yet valid")
	}

	// The nonce binds the token to this login attempt. Without it a token
	// captured from another session at the same provider would be replayable
	// here, which is exactly what the nonce exists to prevent.
	if nonce == "" {
		return Assertion{}, errors.New("no nonce was recorded for this login")
	}
	if subtle.ConstantTimeCompare([]byte(assertion.Nonce), []byte(nonce)) != 1 {
		return Assertion{}, ErrNonceMismatch
	}
	return assertion, nil
}

// selectKey pins the verification key by kid, and refuses to guess.
func selectKey(keys KeySet, keyID, keyType string) (JWK, error) {
	if keyID != "" {
		for _, key := range keys.Keys {
			if key.KeyID == keyID {
				if key.KeyType != keyType {
					return JWK{}, fmt.Errorf(
						"kid %q is a %s key but the token declares a %s algorithm",
						keyID, key.KeyType, keyType)
				}
				return key, nil
			}
		}
		return JWK{}, ErrUnknownKey
	}
	// No kid: acceptable only when the provider publishes exactly one usable
	// key, because then there is nothing to choose. With several, picking one
	// would be guessing at which key an unsigned assertion meant.
	var candidates []JWK
	for _, key := range keys.Keys {
		if key.KeyType == keyType {
			candidates = append(candidates, key)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) == 0 {
		return JWK{}, ErrUnknownKey
	}
	return JWK{}, errors.New(
		"the ID token declares no kid and the provider publishes several keys of that type")
}

func verifySignature(spec algorithm, key JWK, signed, signature []byte) error {
	digest := spec.newHash()
	digest.Write(signed)
	sum := digest.Sum(nil)

	switch spec.keyType {
	case "RSA":
		public, err := rsaPublicKey(key)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(public, spec.hash, sum, signature); err != nil {
			return errors.New("the ID token signature is invalid")
		}
		return nil
	case "EC":
		public, err := ecdsaPublicKey(key, spec.curve)
		if err != nil {
			return err
		}
		// JOSE uses the fixed-width r||s form, not ASN.1, so the length is
		// determined by the curve and a mismatch is malformed input.
		size := (spec.curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return errors.New("the ID token signature has the wrong length for its curve")
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(public, sum, r, s) {
			return errors.New("the ID token signature is invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type %q", spec.keyType)
	}
}

func rsaPublicKey(key JWK) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(key.Modulus)
	if err != nil || len(modulus) == 0 {
		return nil, errors.New("the provider's RSA key has an unreadable modulus")
	}
	exponent, err := base64.RawURLEncoding.DecodeString(key.Exponent)
	if err != nil || len(exponent) == 0 || len(exponent) > 8 {
		return nil, errors.New("the provider's RSA key has an unreadable exponent")
	}
	// 2048 bits is the floor every current guideline agrees on, and a short
	// modulus is the cheapest way to make a signature forgeable.
	if len(modulus)*8 < 2048 {
		return nil, fmt.Errorf(
			"the provider's RSA key is %d bits; SESAME requires at least 2048", len(modulus)*8)
	}
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus)}
	value := new(big.Int).SetBytes(exponent)
	if !value.IsInt64() || value.Int64() < 3 || value.Int64() > 1<<31 {
		return nil, errors.New("the provider's RSA key has an out-of-range exponent")
	}
	public.E = int(value.Int64())
	return public, nil
}

func ecdsaPublicKey(key JWK, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	expected := map[elliptic.Curve]string{
		elliptic.P256(): "P-256",
		elliptic.P384(): "P-384",
		elliptic.P521(): "P-521",
	}[curve]
	if key.Curve != expected {
		return nil, fmt.Errorf(
			"the token declares a %s algorithm but the key is on curve %q", expected, key.Curve)
	}
	x, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil || len(x) == 0 {
		return nil, errors.New("the provider's EC key has an unreadable x coordinate")
	}
	y, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil || len(y) == 0 {
		return nil, errors.New("the provider's EC key has an unreadable y coordinate")
	}
	public := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	// A point off the curve is not a key. Go's ecdsa.Verify does not check
	// this for us, and an off-curve point can make verification behave in
	// ways the caller does not expect.
	if !curve.IsOnCurve(public.X, public.Y) {
		return nil, errors.New("the provider's EC key is not a point on its declared curve")
	}
	return public, nil
}

// matchAudience enforces that this token was issued for SESAME.
func matchAudience(claims map[string]any, clientID string) (string, error) {
	switch value := claims["aud"].(type) {
	case string:
		if value != clientID {
			return "", fmt.Errorf(
				"the ID token is addressed to %q, not to this client", value)
		}
		return value, nil
	case []any:
		found := false
		for _, entry := range value {
			if text, ok := entry.(string); ok && text == clientID {
				found = true
				break
			}
		}
		if !found {
			return "", errors.New("the ID token audience does not include this client")
		}
		// With several audiences the specification requires azp, and requires
		// it to be this client. Skipping it would let a token minted for a
		// different relying party — which happens to list SESAME too — be
		// replayed here.
		if len(value) > 1 {
			if authorized := stringClaim(claims, "azp"); authorized != clientID {
				return "", errors.New(
					"the ID token has multiple audiences and its azp is not this client")
			}
		}
		return clientID, nil
	default:
		return "", errors.New("the ID token carries no audience")
	}
}

func decodeSegment(segment string, target any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return fmt.Errorf("segment is not base64url: %w", err)
	}
	if len(raw) > MaxDocumentBytes {
		return ErrDocumentTooLarge
	}
	return json.Unmarshal(raw, target)
}

func stringClaim(claims map[string]any, key string) string {
	if value, ok := claims[key].(string); ok {
		return value
	}
	return ""
}

func intClaim(claims map[string]any, key string) int64 {
	switch value := claims[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case json.Number:
		parsed, err := value.Int64()
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}
