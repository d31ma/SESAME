// Package token issues and verifies the signed tokens SESAME hands to
// relying parties.
//
// Signing keys live in the deployment key directory, never in a FYLO
// document: a stolen data root must not yield the ability to mint tokens.
// Only the public half is ever published, through JWKS.
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	// AlgorithmES256 is the only signing algorithm SESAME accepts.
	//
	// A single algorithm is deliberate: the classic JWT failure is a
	// verifier that honours whatever `alg` a token header claims, including
	// "none" or a symmetric algorithm keyed by the public key. There is
	// nothing to negotiate here, so nothing to confuse.
	AlgorithmES256 = "ES256"

	// KeyTypeEC and CurveP256 describe the published JWKS entry.
	KeyTypeEC = "EC"
	CurveP256 = "P-256"

	coordinateBytes = 32
	// MaxClockSkew tolerates modest disagreement between the issuer's clock
	// and a verifier's without letting an expired token live indefinitely.
	MaxClockSkew = 60 * time.Second
)

// ErrNoSigningKey reports token work attempted without a configured key.
var ErrNoSigningKey = errors.New("no signing key is configured; run sesame init to create a deployment")

// SigningKey is one ES256 key pair with a stable identifier.
type SigningKey struct {
	ID          string
	private     *ecdsa.PrivateKey
	publicPoint []byte
}

// NewSigningKey generates a fresh P-256 key.
func NewSigningKey() (*SigningKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return newSigningKey(private)
}

func newSigningKey(private *ecdsa.PrivateKey) (*SigningKey, error) {
	// The identifier is derived from the public key, so the same key always
	// carries the same kid and a rotated key cannot silently reuse one.
	publicPoint, err := private.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode public key point: %w", err)
	}
	public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	digest := sha256.Sum256(public)
	return &SigningKey{
		ID:          base64.RawURLEncoding.EncodeToString(digest[:16]),
		private:     private,
		publicPoint: publicPoint,
	}, nil
}

// EncodeSigningKey writes the private key as PKCS#8 PEM for the deployment
// key directory.
func EncodeSigningKey(key *SigningKey) ([]byte, error) {
	if key == nil || key.private == nil {
		return nil, ErrNoSigningKey
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key.private)
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), nil
}

// ParseSigningKey reads a PKCS#8 PEM private key and rejects anything that is
// not a P-256 key.
func ParseSigningKey(encoded []byte) (*SigningKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("signing key must be a PKCS#8 PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || private.Curve != elliptic.P256() {
		return nil, errors.New("signing key must be an ECDSA P-256 key")
	}
	return newSigningKey(private)
}

// JWK is one published public key.
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

// JWKS is the published key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK returns the published form of the key. It contains no private
// component: the D parameter is never marshalled anywhere in this package.
func (k *SigningKey) PublicJWK() JWK {
	return JWK{
		KeyType:   KeyTypeEC,
		Use:       "sig",
		Algorithm: AlgorithmES256,
		KeyID:     k.ID,
		Curve:     CurveP256,
		X:         base64.RawURLEncoding.EncodeToString(k.publicPoint[1 : 1+coordinateBytes]),
		Y:         base64.RawURLEncoding.EncodeToString(k.publicPoint[1+coordinateBytes:]),
	}
}

func padCoordinate(value *big.Int) []byte {
	padded := make([]byte, coordinateBytes)
	value.FillBytes(padded)
	return padded
}

// Claims are the registered claims SESAME issues. Extra carries the
// token-specific claims such as scope or nonce.
type Claims struct {
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	Audience  string         `json:"aud"`
	ExpiresAt int64          `json:"exp"`
	IssuedAt  int64          `json:"iat"`
	NotBefore int64          `json:"nbf"`
	ID        string         `json:"jti"`
	Extra     map[string]any `json:"-"`
}

// Sign produces a compact JWS.
func (k *SigningKey) Sign(claims Claims) (string, error) {
	if k == nil || k.private == nil {
		return "", ErrNoSigningKey
	}
	header := map[string]string{"alg": AlgorithmES256, "typ": "JWT", "kid": k.ID}
	encodedHeader, err := encodeSegment(header)
	if err != nil {
		return "", err
	}

	body := map[string]any{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"exp": claims.ExpiresAt,
		"iat": claims.IssuedAt,
		"nbf": claims.NotBefore,
		"jti": claims.ID,
	}
	for key, value := range claims.Extra {
		// Registered claims are owned by the issuer and cannot be shadowed
		// by a caller-supplied extra claim.
		if _, reserved := body[key]; reserved {
			return "", fmt.Errorf("claim %q is reserved", key)
		}
		body[key] = value
	}
	encodedBody, err := encodeSegment(body)
	if err != nil {
		return "", err
	}

	signingInput := encodedHeader + "." + encodedBody
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	signature := append(padCoordinate(r), padCoordinate(s)...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Verify checks a compact JWS against this key and returns its claims.
//
// The header's algorithm and key identifier must match this key exactly. A
// token is never verified with an algorithm it chose for itself.
func (k *SigningKey) Verify(compact, issuer, audience string, now time.Time) (Claims, map[string]any, error) {
	return k.verify(compact, issuer, audience, now, true)
}

// VerifyExpired checks a token exactly as Verify does but tolerates one that
// has passed its expiry.
//
// This exists for one caller: an `id_token_hint` at the logout endpoint. That
// token is not authorizing anything — it names a session to end — and OpenID
// Connect RP-Initiated Logout expects an expired hint to work, because the
// user reaching for "sign out" is often doing so precisely because their
// tokens have aged. The cost is bounded: an attacker holding an old ID token
// can end a session, which only ever reduces access and is idempotent.
// Signature, issuer, audience, and key identifier are all still enforced.
func (k *SigningKey) VerifyExpired(compact, issuer, audience string, now time.Time) (Claims, map[string]any, error) {
	return k.verify(compact, issuer, audience, now, false)
}

func (k *SigningKey) verify(
	compact, issuer, audience string,
	now time.Time,
	enforceExpiry bool,
) (Claims, map[string]any, error) {
	if k == nil || k.private == nil {
		return Claims{}, nil, ErrNoSigningKey
	}
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		return Claims{}, nil, errors.New("token is not a compact JWS")
	}

	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}
	if err := decodeSegment(segments[0], &header); err != nil {
		return Claims{}, nil, fmt.Errorf("decode token header: %w", err)
	}
	if header.Algorithm != AlgorithmES256 {
		return Claims{}, nil, fmt.Errorf("unsupported token algorithm %q", header.Algorithm)
	}
	if header.KeyID != k.ID {
		return Claims{}, nil, errors.New("token was signed by a different key")
	}

	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil || len(signature) != coordinateBytes*2 {
		return Claims{}, nil, errors.New("token signature is malformed")
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	r := new(big.Int).SetBytes(signature[:coordinateBytes])
	s := new(big.Int).SetBytes(signature[coordinateBytes:])
	if !ecdsa.Verify(&k.private.PublicKey, digest[:], r, s) {
		return Claims{}, nil, errors.New("token signature is invalid")
	}

	var body map[string]any
	if err := decodeSegment(segments[1], &body); err != nil {
		return Claims{}, nil, fmt.Errorf("decode token claims: %w", err)
	}
	claims := Claims{
		Issuer:   stringClaim(body, "iss"),
		Subject:  stringClaim(body, "sub"),
		Audience: stringClaim(body, "aud"),
		ID:       stringClaim(body, "jti"),
	}
	claims.ExpiresAt = intClaim(body, "exp")
	claims.IssuedAt = intClaim(body, "iat")
	claims.NotBefore = intClaim(body, "nbf")

	if claims.Issuer != issuer {
		return Claims{}, nil, errors.New("token issuer does not match")
	}
	if audience != "" && claims.Audience != audience {
		return Claims{}, nil, errors.New("token audience does not match")
	}
	if claims.ExpiresAt == 0 {
		// An unbounded token is refused even where expiry is tolerated: a
		// token that never expires is a different thing from an old one.
		return Claims{}, nil, errors.New("token has no expiry")
	}
	if enforceExpiry && now.After(time.Unix(claims.ExpiresAt, 0).Add(MaxClockSkew)) {
		return Claims{}, nil, errors.New("token has expired")
	}
	if claims.NotBefore != 0 && now.Add(MaxClockSkew).Before(time.Unix(claims.NotBefore, 0)) {
		return Claims{}, nil, errors.New("token is not yet valid")
	}
	return claims, body, nil
}

func encodeSegment(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode token segment: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeSegment(segment string, target any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return errors.New("segment is not base64url")
	}
	return json.Unmarshal(decoded, target)
}

func stringClaim(body map[string]any, key string) string {
	if value, ok := body[key].(string); ok {
		return value
	}
	return ""
}

func intClaim(body map[string]any, key string) int64 {
	if value, ok := body[key].(float64); ok {
		return int64(value)
	}
	return 0
}
