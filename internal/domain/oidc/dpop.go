package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// DPoP (RFC 9449) turns an access token from a bearer credential into one that
// only its holder can use.
//
// A bearer token is whoever has it. Every layer between the client and the
// resource — a proxy, a log, a browser extension, a leaked backup — is a place
// it can be picked up and replayed, and nothing about the token itself objects.
// DPoP fixes that by having the client keep a key pair and sign a fresh proof
// for every request; the token carries the key's thumbprint, so a token
// captured without the private key is worth nothing.
//
// Three things make that hold, and each is enforced below rather than assumed:
// the proof is bound to one HTTP method and URI, so it cannot be lifted onto
// another endpoint; it is bound to one access token via `ath`, so it cannot be
// lifted onto another token; and its `jti` is spent durably, so it cannot be
// replayed at all within its window.
//
// # What the engine cannot see
//
// SESAME opens no network listener and speaks no HTTP. The method and URI a
// proof claims are therefore checked against values the *host* asserts, not
// against a request the engine observed. That is a real trust boundary and it
// is named here deliberately: a host that reports the wrong URI defeats the
// binding, exactly as a host that skips the check entirely would. What the
// engine can still guarantee — and does — is that the asserted URI belongs to
// this deployment's issuer origin, so even a careless host cannot be walked
// into honouring a proof minted for somebody else's server.

const (
	// EventDPoPProofSpent records a proof identifier being consumed. Durable,
	// so a replay is refused across a restart.
	EventDPoPProofSpent = "oidc.dpop_proof_spent"

	// DPoPProofType is the required `typ` header. RFC 9449 mandates it so a
	// proof can never be mistaken for — or substituted by — an ordinary JWT
	// minted for another purpose.
	DPoPProofType = "dpop+jwt"

	// DPoPProofLifetime bounds how far from now a proof's `iat` may sit. A
	// proof is created immediately before the request it accompanies, so the
	// window only has to cover clock skew and flight time. It doubles as the
	// horizon for the replay store: a proof older than this is refused on its
	// timestamp, so its identifier need not be remembered beyond it.
	DPoPProofLifetime = 60 * time.Second

	// DPoPConfirmationClaim is the confirmation claim RFC 9449 binds tokens
	// with. Its `jkt` member is the thumbprint of the client's public key.
	DPoPConfirmationClaim = "cnf"
	// DPoPThumbprintClaim is the member inside `cnf`.
	DPoPThumbprintClaim = "jkt"

	// TokenTypeDPoP is the token type an access token is issued as once it is
	// key-bound. A client must present it as `Authorization: DPoP <token>`,
	// and the different scheme is the point: a DPoP-bound token handed to a
	// resource server expecting `Bearer` fails loudly instead of being
	// accepted without its proof.
	TokenTypeDPoP = "DPoP"

	// maxDPoPProofBytes bounds a proof before anything parses it. A proof is a
	// small fixed-shape JWT; anything larger is not one, and refusing early
	// keeps a decoder from doing work on an attacker's behalf.
	maxDPoPProofBytes = 4096
	// maxDPoPIdentifierRunes bounds `jti`, which is stored.
	maxDPoPIdentifierRunes = 128

	// These mirror the token package's constants, as AlgorithmES256 already
	// does. A contract test asserts the two agree, so the domain does not have
	// to import the signing package to describe a key it never signs with.
	dpopKeyType     = "EC"
	dpopCurve       = "P-256"
	coordinateBytes = 32
	// dpopClockSkew tolerates modest disagreement between the client's clock
	// and this deployment's.
	dpopClockSkew = 60 * time.Second
)

// Stable DPoP failures. They are distinct because a host maps them to
// different HTTP responses: `use_dpop_nonce` behaviour aside, an invalid proof
// is a 400 at the token endpoint and a 401 at a resource.
var (
	// ErrDPoPProofMalformed covers everything structural: not a JWS, wrong
	// `typ`, wrong algorithm, an unusable key, a bad signature.
	ErrDPoPProofMalformed = errors.New("DPoP proof is malformed")
	// ErrDPoPProofNotBound reports a proof whose method, URI, or access-token
	// hash does not match the request it arrived with.
	ErrDPoPProofNotBound = errors.New("DPoP proof is not bound to this request")
	// ErrDPoPProofExpired reports a proof whose `iat` sits outside the window.
	ErrDPoPProofExpired = errors.New("DPoP proof is outside its validity window")
	// ErrDPoPKeyMismatch reports a proof signed by a key other than the one
	// the token is bound to.
	ErrDPoPKeyMismatch = errors.New("DPoP proof key does not match the token binding")
)

// DPoPProof is one validated proof-of-possession.
//
// It holds no key material beyond the thumbprint. The public key itself has
// done its work by the time this is returned — it verified the signature — and
// keeping it would invite a caller to trust a key the proof chose for itself.
type DPoPProof struct {
	// Thumbprint is the RFC 7638 thumbprint of the proof's public key. This is
	// what a token is bound to.
	Thumbprint string
	// ID is the proof's `jti`, spent durably to stop replay.
	ID string
	// Method and URI are the request the proof claims to accompany.
	Method string
	URI    string
	// IssuedAt is the proof's `iat`.
	IssuedAt time.Time
	// AccessTokenHash is the `ath` claim, empty when the proof carried none.
	AccessTokenHash string
}

// DPoPProofSpentPayload is the versioned payload of EventDPoPProofSpent.
//
// The thumbprint is recorded beside the identifier because `jti` is unique
// only per client key: two clients picking the same identifier is unlikely but
// not forbidden, and treating one as a replay of the other would refuse a
// legitimate request.
type DPoPProofSpentPayload struct {
	ProofID    string `json:"dpop_proof_id"`
	Thumbprint string `json:"dpop_thumbprint"`
	TenantID   string `json:"tenant_id"`
	SpentAt    string `json:"spent_at"`
	ExpiresAt  string `json:"expires_at"`
}

// ParseDPoPProof validates a proof's structure and signature and returns what
// it claims.
//
// It deliberately does not check the method, URI, or token hash: those depend
// on a request the engine did not observe, so they are checked by the caller
// that holds the host's assertion. What is checked here is everything
// self-contained — and the signature is verified under the key the proof
// carries, which is sound only because the thumbprint of that key is then
// matched against what the token was bound to. A proof that verifies under its
// own key proves nothing on its own; it proves possession only once the
// thumbprint matches.
func ParseDPoPProof(compact string) (DPoPProof, error) {
	if compact == "" {
		return DPoPProof{}, fmt.Errorf("%w: no proof was presented", ErrDPoPProofMalformed)
	}
	if len(compact) > maxDPoPProofBytes {
		return DPoPProof{}, fmt.Errorf("%w: proof exceeds %d bytes",
			ErrDPoPProofMalformed, maxDPoPProofBytes)
	}
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		return DPoPProof{}, fmt.Errorf("%w: not a compact JWS", ErrDPoPProofMalformed)
	}

	header, key, err := parseDPoPHeader(segments[0])
	if err != nil {
		return DPoPProof{}, err
	}
	if err := verifyDPoPSignature(segments, key); err != nil {
		return DPoPProof{}, err
	}

	var body struct {
		ID              string  `json:"jti"`
		Method          string  `json:"htm"`
		URI             string  `json:"htu"`
		IssuedAt        float64 `json:"iat"`
		AccessTokenHash string  `json:"ath"`
	}
	if err := decodeDPoPSegment(segments[1], &body); err != nil {
		return DPoPProof{}, fmt.Errorf("%w: %v", ErrDPoPProofMalformed, err)
	}
	if body.ID == "" || len([]rune(body.ID)) > maxDPoPIdentifierRunes {
		return DPoPProof{}, fmt.Errorf("%w: jti must be 1 to %d characters",
			ErrDPoPProofMalformed, maxDPoPIdentifierRunes)
	}
	if body.Method == "" || body.URI == "" {
		return DPoPProof{}, fmt.Errorf("%w: htm and htu are required", ErrDPoPProofMalformed)
	}
	if body.IssuedAt == 0 {
		return DPoPProof{}, fmt.Errorf("%w: iat is required", ErrDPoPProofMalformed)
	}

	return DPoPProof{
		Thumbprint:      header,
		ID:              body.ID,
		Method:          body.Method,
		URI:             body.URI,
		IssuedAt:        time.Unix(int64(body.IssuedAt), 0).UTC(),
		AccessTokenHash: body.AccessTokenHash,
	}, nil
}

// parseDPoPHeader validates the header and returns the thumbprint of the
// embedded key together with the key itself.
func parseDPoPHeader(segment string) (string, *ecdsa.PublicKey, error) {
	var header struct {
		Algorithm string          `json:"alg"`
		Type      string          `json:"typ"`
		Key       json.RawMessage `json:"jwk"`
	}
	if err := decodeDPoPSegment(segment, &header); err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrDPoPProofMalformed, err)
	}
	if header.Type != DPoPProofType {
		return "", nil, fmt.Errorf("%w: typ must be %q", ErrDPoPProofMalformed, DPoPProofType)
	}
	// One algorithm, matched exactly. SESAME signs with ES256 and accepts
	// nothing else anywhere; an allowlist with a single entry is the same
	// refusal to negotiate that makes `alg:none` and HS256 confusion
	// structurally impossible rather than filtered.
	if header.Algorithm != AlgorithmES256 {
		return "", nil, fmt.Errorf("%w: unsupported proof algorithm %q",
			ErrDPoPProofMalformed, header.Algorithm)
	}
	if len(header.Key) == 0 {
		return "", nil, fmt.Errorf("%w: jwk is required", ErrDPoPProofMalformed)
	}
	return parseDPoPKey(header.Key)
}

// parseDPoPKey reads the embedded public key and computes its thumbprint.
func parseDPoPKey(raw json.RawMessage) (string, *ecdsa.PublicKey, error) {
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil {
		return "", nil, fmt.Errorf("%w: jwk is not an object", ErrDPoPProofMalformed)
	}
	// A private component in a public key is not a formatting slip. Accepting
	// it would mean thumbprinting a key whose canonical form RFC 7638 says to
	// compute from public members only — so the same key with and without `d`
	// would bind identically, and a client could leak its own secret into a
	// value the engine stores and logs.
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, present := members[private]; present {
			return "", nil, fmt.Errorf("%w: jwk carries the private member %q",
				ErrDPoPProofMalformed, private)
		}
	}
	keyType, _ := members["kty"].(string)
	curve, _ := members["crv"].(string)
	x, _ := members["x"].(string)
	y, _ := members["y"].(string)
	if keyType != dpopKeyType || curve != dpopCurve {
		return "", nil, fmt.Errorf("%w: jwk must be an %s key on %s",
			ErrDPoPProofMalformed, dpopKeyType, dpopCurve)
	}

	key, err := decodeP256Coordinates(x, y)
	if err != nil {
		return "", nil, err
	}
	return JWKThumbprint(curve, keyType, x, y), key, nil
}

// decodeP256Coordinates turns the JWK coordinates into a usable public key.
//
// The point is checked to be on the curve. An off-curve point is not a
// mis-encoding to tolerate: ECDSA verification against one is the classic
// invalid-curve attack, and the check costs nothing.
func decodeP256Coordinates(x, y string) (*ecdsa.PublicKey, error) {
	decodedX, errX := base64.RawURLEncoding.DecodeString(x)
	decodedY, errY := base64.RawURLEncoding.DecodeString(y)
	if errX != nil || errY != nil ||
		len(decodedX) != coordinateBytes || len(decodedY) != coordinateBytes {
		return nil, fmt.Errorf("%w: jwk coordinates must be %d base64url bytes",
			ErrDPoPProofMalformed, coordinateBytes)
	}
	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(decodedX),
		Y:     new(big.Int).SetBytes(decodedY),
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, fmt.Errorf("%w: jwk point is not on %s", ErrDPoPProofMalformed, dpopCurve)
	}
	return key, nil
}

func verifyDPoPSignature(segments []string, key *ecdsa.PublicKey) error {
	signature, err := base64.RawURLEncoding.DecodeString(segments[2])
	if err != nil || len(signature) != coordinateBytes*2 {
		return fmt.Errorf("%w: signature is not a %d-byte ES256 signature",
			ErrDPoPProofMalformed, coordinateBytes*2)
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	r := new(big.Int).SetBytes(signature[:coordinateBytes])
	s := new(big.Int).SetBytes(signature[coordinateBytes:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return fmt.Errorf("%w: signature does not verify under the proof's own key",
			ErrDPoPProofMalformed)
	}
	return nil
}

// JWKThumbprint computes the RFC 7638 thumbprint of a P-256 public key.
//
// The canonical form is built by hand rather than by marshalling a struct:
// RFC 7638 requires exactly the required members, in lexicographic order, with
// no whitespace, and a struct's field order is a property of the source file
// rather than of the specification. Getting this wrong would not fail loudly —
// it would produce a stable thumbprint that no other implementation agrees
// with.
func JWKThumbprint(curve, keyType, x, y string) string {
	canonical := `{"crv":"` + curve + `","kty":"` + keyType +
		`","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AccessTokenHash computes the `ath` claim binding a proof to one token.
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// BindProofToRequest checks the parts of a proof that depend on the request it
// arrived with.
//
// The method and URI come from the host, which is the only party that saw the
// HTTP request. `accessToken` is empty at the token endpoint, where no token
// exists yet, and required everywhere else: a proof presented with a token but
// carrying no `ath` is refused rather than accepted as unbound, because
// accepting it would let one proof be lifted from a cheap endpoint onto an
// expensive one.
func (p DPoPProof) BindProofToRequest(method, uri, accessToken string, now time.Time) error {
	if !strings.EqualFold(p.Method, method) {
		return fmt.Errorf("%w: proof is for %s, request was %s",
			ErrDPoPProofNotBound, p.Method, method)
	}
	claimed, err := NormalizeDPoPURI(p.URI)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDPoPProofNotBound, err)
	}
	served, err := NormalizeDPoPURI(uri)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDPoPProofNotBound, err)
	}
	if claimed != served {
		return fmt.Errorf("%w: proof is for a different URI", ErrDPoPProofNotBound)
	}
	if accessToken != "" {
		if p.AccessTokenHash == "" {
			return fmt.Errorf("%w: a proof presented with an access token must carry ath",
				ErrDPoPProofNotBound)
		}
		if subtle.ConstantTimeCompare([]byte(p.AccessTokenHash),
			[]byte(AccessTokenHash(accessToken))) != 1 {
			return fmt.Errorf("%w: ath is for a different access token", ErrDPoPProofNotBound)
		}
	}
	if err := p.WithinWindow(now); err != nil {
		return err
	}
	return nil
}

// WithinWindow checks the proof's `iat` in both directions.
//
// Future-dated proofs are refused as firmly as stale ones. A client whose
// clock runs fast could otherwise mint proofs valid long after the window
// they were meant for, which is the replay the window exists to bound.
func (p DPoPProof) WithinWindow(now time.Time) error {
	if p.IssuedAt.Before(now.Add(-DPoPProofLifetime)) {
		return fmt.Errorf("%w: proof is older than %s", ErrDPoPProofExpired, DPoPProofLifetime)
	}
	if p.IssuedAt.After(now.Add(dpopClockSkew)) {
		return fmt.Errorf("%w: proof is dated in the future", ErrDPoPProofExpired)
	}
	return nil
}

// NormalizeDPoPURI reduces a URI to what RFC 9449 compares: scheme, host, and
// path, with the query and fragment removed.
//
// Normalization is narrow on purpose. Lower-casing the scheme and host and
// dropping a default port are safe because they cannot change which resource
// is named; anything more — resolving `..`, decoding escapes, stripping a
// trailing slash — would let two URIs the host distinguishes compare equal
// here, which is how a proof for one endpoint becomes valid at another.
func NormalizeDPoPURI(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("htu is not a URI")
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("htu must be an absolute URI")
	}
	if parsed.User != nil {
		// Userinfo in an htu is never legitimate and is the oldest way to make
		// a URI read as one host while naming another.
		return "", errors.New("htu must not carry userinfo")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("htu scheme %q is not addressable", parsed.Scheme)
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimSuffix(host, ":443")
	if scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// SameOrigin reports whether a URI belongs to the given issuer's origin.
//
// This is the one binding check the engine can make without trusting the host:
// whatever URI the host reports having served, it must be one of this
// deployment's own. A proof minted for another authorization server is
// therefore refused even by a host that reported it faithfully.
func SameOrigin(uri, issuer string) bool {
	target, err := url.Parse(uri)
	if err != nil {
		return false
	}
	origin, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	if target.Scheme == "" || target.Host == "" || origin.Scheme == "" || origin.Host == "" {
		return false
	}
	return strings.EqualFold(target.Scheme, origin.Scheme) &&
		strings.EqualFold(target.Host, origin.Host)
}

func decodeDPoPSegment(segment string, target any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return errors.New("segment is not base64url")
	}
	return json.Unmarshal(decoded, target)
}
