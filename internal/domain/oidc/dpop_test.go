package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// dpopSigner is a test client holding a DPoP key.
type dpopSigner struct {
	private     *ecdsa.PrivateKey
	publicPoint []byte
}

func newDPoPSigner(t *testing.T) *dpopSigner {
	t.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	return &dpopSigner{private: private, publicPoint: mustPublicPoint(t, private)}
}

func mustPublicPoint(t testing.TB, private *ecdsa.PrivateKey) []byte {
	t.Helper()

	point, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	return point
}

func (d *dpopSigner) jwk() map[string]any {
	return map[string]any{
		"kty": dpopKeyType,
		"crv": dpopCurve,
		"x":   base64.RawURLEncoding.EncodeToString(d.publicPoint[1 : 1+coordinateBytes]),
		"y":   base64.RawURLEncoding.EncodeToString(d.publicPoint[1+coordinateBytes:]),
	}
}

func (d *dpopSigner) thumbprint() string {
	key := d.jwk()
	return JWKThumbprint(key["crv"].(string), key["kty"].(string),
		key["x"].(string), key["y"].(string))
}

// sign mints a proof from arbitrary header and body maps, so a test can build
// a malformed one as easily as a valid one.
func (d *dpopSigner) sign(t *testing.T, header, body map[string]any) string {
	t.Helper()

	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal proof segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	input := encode(header) + "." + encode(body)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, d.private, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	signature := append(r.FillBytes(make([]byte, coordinateBytes)),
		s.FillBytes(make([]byte, coordinateBytes))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (d *dpopSigner) header() map[string]any {
	return map[string]any{"typ": DPoPProofType, "alg": AlgorithmES256, "jwk": d.jwk()}
}

func dpopBody(id, method, uri string, issuedAt time.Time) map[string]any {
	return map[string]any{"jti": id, "htm": method, "htu": uri, "iat": issuedAt.Unix()}
}

// proof mints a valid proof for one request.
func (d *dpopSigner) proof(t *testing.T, id, method, uri string, issuedAt time.Time) string {
	t.Helper()
	return d.sign(t, d.header(), dpopBody(id, method, uri, issuedAt))
}

const (
	dpopTokenURI = "https://id.example/oauth/token"
	dpopNow      = 1_700_000_000
)

func dpopClock() time.Time { return time.Unix(dpopNow, 0).UTC() }

// TestValidProofParsesAndBinds is the happy path.
func TestValidProofParsesAndBinds(t *testing.T) {
	t.Parallel()

	signer := newDPoPSigner(t)
	parsed, err := ParseDPoPProof(signer.proof(t, "proof-1", "POST", dpopTokenURI, dpopClock()))
	if err != nil {
		t.Fatalf("ParseDPoPProof() error = %v", err)
	}
	if parsed.Thumbprint != signer.thumbprint() {
		t.Fatalf("thumbprint = %q, want %q", parsed.Thumbprint, signer.thumbprint())
	}
	if parsed.ID != "proof-1" {
		t.Fatalf("jti = %q", parsed.ID)
	}
	if err := parsed.BindProofToRequest("POST", dpopTokenURI, "", dpopClock()); err != nil {
		t.Fatalf("BindProofToRequest() error = %v", err)
	}
}

// TestProofStructureIsRefusedNotRepaired.
//
// Every case here is a proof that a lenient parser would accept and a correct
// one must not. `alg: none` and a symmetric algorithm are the classic JWT
// failures; a private member in the `jwk` would leak a client's own secret
// into a value the engine stores; an off-curve point is the invalid-curve
// attack.
func TestProofStructureIsRefusedNotRepaired(t *testing.T) {
	t.Parallel()

	signer := newDPoPSigner(t)
	valid := signer.proof(t, "proof-1", "POST", dpopTokenURI, dpopClock())

	private := signer.jwk()
	privateBytes, err := signer.private.Bytes()
	if err != nil {
		t.Fatalf("encode private key: %v", err)
	}
	private["d"] = base64.RawURLEncoding.EncodeToString(privateBytes)

	offCurve := signer.jwk()
	offCurve["y"] = base64.RawURLEncoding.EncodeToString(make([]byte, coordinateBytes))

	for name, compact := range map[string]string{
		"an empty proof":        "",
		"not a JWS":             "not-a-jws",
		"two segments":          strings.Join(strings.Split(valid, ".")[:2], "."),
		"four segments":         valid + ".extra",
		"a truncated signature": strings.Join(strings.Split(valid, ".")[:2], ".") + ".AAAA",
		"an ordinary JWT typ": signer.sign(t,
			map[string]any{"typ": "JWT", "alg": AlgorithmES256, "jwk": signer.jwk()},
			dpopBody("p", "POST", dpopTokenURI, dpopClock())),
		"alg none": signer.sign(t,
			map[string]any{"typ": DPoPProofType, "alg": "none", "jwk": signer.jwk()},
			dpopBody("p", "POST", dpopTokenURI, dpopClock())),
		"a symmetric alg": signer.sign(t,
			map[string]any{"typ": DPoPProofType, "alg": "HS256", "jwk": signer.jwk()},
			dpopBody("p", "POST", dpopTokenURI, dpopClock())),
		"no jwk": signer.sign(t,
			map[string]any{"typ": DPoPProofType, "alg": AlgorithmES256},
			dpopBody("p", "POST", dpopTokenURI, dpopClock())),
		"a private jwk": signer.sign(t,
			map[string]any{"typ": DPoPProofType, "alg": AlgorithmES256, "jwk": private},
			dpopBody("p", "POST", dpopTokenURI, dpopClock())),
		"an off-curve point": signer.sign(t,
			map[string]any{"typ": DPoPProofType, "alg": AlgorithmES256, "jwk": offCurve},
			dpopBody("p", "POST", dpopTokenURI, dpopClock())),
		"an RSA jwk": signer.sign(t,
			map[string]any{"typ": DPoPProofType, "alg": AlgorithmES256,
				"jwk": map[string]any{"kty": "RSA", "n": "AAAA", "e": "AQAB"}},
			dpopBody("p", "POST", dpopTokenURI, dpopClock())),
		"the wrong curve": signer.sign(t,
			map[string]any{"typ": DPoPProofType, "alg": AlgorithmES256,
				"jwk": map[string]any{"kty": dpopKeyType, "crv": "P-384",
					"x": signer.jwk()["x"], "y": signer.jwk()["y"]}},
			dpopBody("p", "POST", dpopTokenURI, dpopClock())),
		"no jti": signer.sign(t, signer.header(),
			map[string]any{"htm": "POST", "htu": dpopTokenURI, "iat": dpopNow}),
		"an oversized jti": signer.sign(t, signer.header(),
			dpopBody(strings.Repeat("j", maxDPoPIdentifierRunes+1), "POST", dpopTokenURI, dpopClock())),
		"no htm": signer.sign(t, signer.header(),
			map[string]any{"jti": "p", "htu": dpopTokenURI, "iat": dpopNow}),
		"no htu": signer.sign(t, signer.header(),
			map[string]any{"jti": "p", "htm": "POST", "iat": dpopNow}),
		"no iat": signer.sign(t, signer.header(),
			map[string]any{"jti": "p", "htm": "POST", "htu": dpopTokenURI}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseDPoPProof(compact); !errors.Is(err, ErrDPoPProofMalformed) {
				t.Fatalf("%s: err = %v, want ErrDPoPProofMalformed", name, err)
			}
		})
	}
}

// TestProofIsRefusedWhenAnotherKeySignedIt. Verifying under the key the proof
// carries is only sound because the thumbprint is checked afterwards — but the
// signature still has to be that key's, or a proof could carry one key and be
// signed by another.
func TestProofIsRefusedWhenAnotherKeySignedIt(t *testing.T) {
	t.Parallel()

	signer := newDPoPSigner(t)
	other := newDPoPSigner(t)
	// The header advertises the victim's key; the signature is the attacker's.
	compact := other.sign(t, signer.header(), dpopBody("p", "POST", dpopTokenURI, dpopClock()))

	if _, err := ParseDPoPProof(compact); !errors.Is(err, ErrDPoPProofMalformed) {
		t.Fatalf("a proof signed by a different key parsed: err = %v", err)
	}
}

// TestProofIsRefusedWhenTheBodyIsEdited: the signature covers both segments,
// so changing a claim after signing invalidates the proof.
func TestProofIsRefusedWhenTheBodyIsEdited(t *testing.T) {
	t.Parallel()

	signer := newDPoPSigner(t)
	segments := strings.Split(signer.proof(t, "p", "POST", dpopTokenURI, dpopClock()), ".")
	edited, err := json.Marshal(dpopBody("p", "POST", "https://evil.example/token", dpopClock()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	segments[1] = base64.RawURLEncoding.EncodeToString(edited)

	if _, err := ParseDPoPProof(strings.Join(segments, ".")); !errors.Is(err, ErrDPoPProofMalformed) {
		t.Fatalf("an edited proof parsed: err = %v", err)
	}
}

// TestProofBindsToOneRequest. A proof good for any method or URI could be
// lifted from a cheap endpoint onto an expensive one.
func TestProofBindsToOneRequest(t *testing.T) {
	t.Parallel()

	signer := newDPoPSigner(t)
	parsed, err := ParseDPoPProof(signer.proof(t, "p", "POST", dpopTokenURI, dpopClock()))
	if err != nil {
		t.Fatalf("ParseDPoPProof() error = %v", err)
	}

	for name, request := range map[string]struct{ method, uri string }{
		"a different method": {"GET", dpopTokenURI},
		"a different host":   {"POST", "https://evil.example/oauth/token"},
		"a different path":   {"POST", "https://id.example/oauth/revoke"},
		"a different scheme": {"POST", "http://id.example/oauth/token"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := parsed.BindProofToRequest(request.method, request.uri, "",
				dpopClock()); !errors.Is(err, ErrDPoPProofNotBound) {
				t.Fatalf("%s: err = %v, want ErrDPoPProofNotBound", name, err)
			}
		})
	}

	// The method is compared case-insensitively because HTTP method names are
	// uppercase by convention rather than by the wire, and refusing "post"
	// would break a correct client for no gain.
	if err := parsed.BindProofToRequest("post", dpopTokenURI, "", dpopClock()); err != nil {
		t.Fatalf("a lower-cased method was refused: %v", err)
	}
	// The query and fragment are not compared: RFC 9449 says htu excludes
	// them, and a client cannot know what a proxy will append.
	if err := parsed.BindProofToRequest("POST", dpopTokenURI+"?trace=1#top", "",
		dpopClock()); err != nil {
		t.Fatalf("a query string broke the binding: %v", err)
	}
}

// TestProofBindsToOneAccessToken. Without `ath`, one proof would be valid for
// every token the holder has.
func TestProofBindsToOneAccessToken(t *testing.T) {
	t.Parallel()

	signer := newDPoPSigner(t)
	const token = "the.access.token"

	bound := signer.sign(t, signer.header(), map[string]any{
		"jti": "p", "htm": "POST", "htu": dpopTokenURI,
		"iat": dpopNow, "ath": AccessTokenHash(token),
	})
	parsed, err := ParseDPoPProof(bound)
	if err != nil {
		t.Fatalf("ParseDPoPProof() error = %v", err)
	}
	if err := parsed.BindProofToRequest("POST", dpopTokenURI, token, dpopClock()); err != nil {
		t.Fatalf("BindProofToRequest() error = %v", err)
	}
	if err := parsed.BindProofToRequest("POST", dpopTokenURI, "another.access.token",
		dpopClock()); !errors.Is(err, ErrDPoPProofNotBound) {
		t.Fatalf("a proof matched a different token: err = %v", err)
	}

	// A proof with no ath, presented alongside a token, is refused rather than
	// treated as unbound.
	unbound, err := ParseDPoPProof(signer.proof(t, "p2", "POST", dpopTokenURI, dpopClock()))
	if err != nil {
		t.Fatalf("ParseDPoPProof() error = %v", err)
	}
	if err := unbound.BindProofToRequest("POST", dpopTokenURI, token,
		dpopClock()); !errors.Is(err, ErrDPoPProofNotBound) {
		t.Fatalf("a proof with no ath was accepted with a token: err = %v", err)
	}
}

// TestProofWindowIsBoundedInBothDirections. A future-dated proof is the more
// interesting half: a client whose clock runs fast could otherwise mint proofs
// that stay valid long after the moment they were meant for.
func TestProofWindowIsBoundedInBothDirections(t *testing.T) {
	t.Parallel()

	signer := newDPoPSigner(t)
	parsed, err := ParseDPoPProof(signer.proof(t, "p", "POST", dpopTokenURI, dpopClock()))
	if err != nil {
		t.Fatalf("ParseDPoPProof() error = %v", err)
	}

	if err := parsed.BindProofToRequest("POST", dpopTokenURI, "",
		dpopClock().Add(DPoPProofLifetime+2*time.Second)); !errors.Is(err, ErrDPoPProofExpired) {
		t.Fatalf("a stale proof was accepted: err = %v", err)
	}
	if err := parsed.BindProofToRequest("POST", dpopTokenURI, "",
		dpopClock().Add(-2*dpopClockSkew)); !errors.Is(err, ErrDPoPProofExpired) {
		t.Fatalf("a future-dated proof was accepted: err = %v", err)
	}
	// Modest skew in either direction is tolerated.
	if err := parsed.BindProofToRequest("POST", dpopTokenURI, "",
		dpopClock().Add(-dpopClockSkew/2)); err != nil {
		t.Fatalf("a slightly early proof was refused: %v", err)
	}
}

// TestThumbprintMatchesRFC7638 pins the canonical form against a fixed vector.
//
// This is the one value in DPoP that has to agree byte for byte with every
// other implementation, and getting it wrong would not fail loudly: it would
// produce a stable thumbprint that nobody else computes.
func TestThumbprintMatchesRFC7638(t *testing.T) {
	t.Parallel()

	// RFC 7638 section 3.1 works its example on an RSA key; the rules it sets
	// out — required members only, in lexicographic order, with no whitespace
	// — are what this applies to an EC key. The expected value below was
	// computed independently of this package from those rules, so it catches a
	// reordering of the canonical members rather than merely restating what
	// JWKThumbprint already does.
	const (
		x    = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs"
		y    = "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
		want = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	)
	if got := JWKThumbprint("P-256", "EC", x, y); got != want {
		t.Fatalf("JWKThumbprint() = %q, want %q", got, want)
	}

	// Member order in the canonical form is not a formatting preference.
	if JWKThumbprint("EC", "P-256", x, y) == want {
		t.Fatal("the thumbprint ignores which member is which")
	}
}

// TestNormalizeDPoPURIIsNarrow. Normalization that goes further than the RFC
// lets two URIs the host distinguishes compare equal here, which is how a
// proof for one endpoint becomes valid at another.
func TestNormalizeDPoPURIIsNarrow(t *testing.T) {
	t.Parallel()

	for name, pair := range map[string]struct{ left, right string }{
		"case in the scheme and host": {"HTTPS://ID.EXAMPLE/token", "https://id.example/token"},
		"a default https port":        {"https://id.example:443/token", "https://id.example/token"},
		"a default http port":         {"http://id.example:80/token", "http://id.example/token"},
		"an empty path":               {"https://id.example", "https://id.example/"},
		"a query string":              {"https://id.example/token?a=1", "https://id.example/token"},
		"a fragment":                  {"https://id.example/token#x", "https://id.example/token"},
	} {
		t.Run(name+" is ignored", func(t *testing.T) {
			t.Parallel()

			left, err := NormalizeDPoPURI(pair.left)
			if err != nil {
				t.Fatalf("NormalizeDPoPURI(%q) error = %v", pair.left, err)
			}
			right, err := NormalizeDPoPURI(pair.right)
			if err != nil {
				t.Fatalf("NormalizeDPoPURI(%q) error = %v", pair.right, err)
			}
			if left != right {
				t.Fatalf("%q and %q normalize differently: %q vs %q",
					pair.left, pair.right, left, right)
			}
		})
	}

	for name, pair := range map[string]struct{ left, right string }{
		"a traversal segment": {"https://id.example/a/../token", "https://id.example/token"},
		"a trailing slash":    {"https://id.example/token/", "https://id.example/token"},
		"a percent escape":    {"https://id.example/to%6Ben", "https://id.example/token"},
		"a non-default port":  {"https://id.example:8443/token", "https://id.example/token"},
		"case in the path":    {"https://id.example/Token", "https://id.example/token"},
	} {
		t.Run(name+" is preserved", func(t *testing.T) {
			t.Parallel()

			left, err := NormalizeDPoPURI(pair.left)
			if err != nil {
				t.Fatalf("NormalizeDPoPURI(%q) error = %v", pair.left, err)
			}
			right, err := NormalizeDPoPURI(pair.right)
			if err != nil {
				t.Fatalf("NormalizeDPoPURI(%q) error = %v", pair.right, err)
			}
			if left == right {
				t.Fatalf("%q and %q were normalized to the same value %q; a proof for "+
					"one endpoint is now valid at the other", pair.left, pair.right, left)
			}
		})
	}

	for name, candidate := range map[string]string{
		"a relative URI":    "/token",
		"no host":           "https:///token",
		"userinfo":          "https://user@id.example/token",
		"a non-HTTP scheme": "ftp://id.example/token",
		"a javascript URI":  "javascript:alert(1)",
		"empty":             "",
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			t.Parallel()

			if _, err := NormalizeDPoPURI(candidate); err == nil {
				t.Fatalf("NormalizeDPoPURI(%q) was accepted", candidate)
			}
		})
	}
}

// TestSameOriginIsTheCheckTheEngineCanMakeAlone.
func TestSameOriginIsTheCheckTheEngineCanMakeAlone(t *testing.T) {
	t.Parallel()

	const issuer = "https://id.example"
	for candidate, want := range map[string]bool{
		"https://id.example/oauth/token": true,
		"https://ID.EXAMPLE/token":       true,
		"https://id.example:8443/token":  false,
		"https://evil.example/token":     false,
		"http://id.example/token":        false,
		"https://id.example.evil/token":  false,
		"//id.example/token":             false,
		"not-a-uri":                      false,
	} {
		if got := SameOrigin(candidate, issuer); got != want {
			t.Errorf("SameOrigin(%q, %q) = %v, want %v", candidate, issuer, got, want)
		}
	}
}

// TestOversizedProofsAreRefusedBeforeParsing keeps a decoder from doing work
// on an attacker's behalf.
func TestOversizedProofsAreRefusedBeforeParsing(t *testing.T) {
	t.Parallel()

	if _, err := ParseDPoPProof(strings.Repeat("a", maxDPoPProofBytes+1)); !errors.Is(err,
		ErrDPoPProofMalformed) {
		t.Fatalf("an oversized proof was parsed: err = %v", err)
	}
}
