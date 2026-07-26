package adversarial_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/d31ma/sesame/clients/go/sesame"
)

const (
	tokenURI = issuer + "/oauth/token"
	apiURI   = issuer + "/api/invoices"
)

// clientKey is an attacker's or a victim's DPoP key. Both sides of every case
// below hold a real key and mint real proofs; nothing here relies on an
// attacker being unable to produce a well-formed one.
type clientKey struct{ private *ecdsa.PrivateKey }

func newClientKey(t *testing.T) *clientKey {
	t.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	return &clientKey{private: private}
}

func (c *clientKey) jwk() map[string]any {
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(
			c.private.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(
			c.private.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
}

// signProof mints a proof from arbitrary header and body maps so a test can
// build a hostile one as easily as a valid one.
func (c *clientKey) signProof(t *testing.T, header, body map[string]any) string {
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
	r, s, err := ecdsa.Sign(rand.Reader, c.private, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (c *clientKey) proof(t *testing.T, id, method, uri, accessToken string) string {
	t.Helper()

	body := map[string]any{"jti": id, "htm": method, "htu": uri, "iat": time.Now().Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		body["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return c.signProof(t,
		map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": c.jwk()}, body)
}

// boundTokens runs a real browser flow to a key-bound token set.
func (d *deployment) boundTokens(t *testing.T, key *clientKey,
	session sesame.IssuedSession, proofID string) sesame.TokenResponse {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	response := d.authorize(t, session)
	request := d.tokenRequest(response.Code)
	request.DPoPProof = key.proof(t, proofID, "POST", tokenURI, "")
	request.DPoPMethod = "POST"
	request.DPoPURI = tokenURI

	tokens, err := d.client.TokenExchange(ctx, request)
	if err != nil {
		t.Fatalf("TokenExchange() with a proof error = %v", err)
	}
	if tokens.TokenType != "DPoP" {
		t.Fatalf("token_type = %q; the token was not key-bound", tokens.TokenType)
	}
	return tokens
}

// TestStolenTokenReplay is the attack DPoP exists to stop.
//
// Assume the worst case short of key theft: the attacker has the access token
// in full, knows the resource, and can mint syntactically perfect proofs with
// a key of their own. Every case below is a real attempt run against a real
// binary, and every one has to fail.
func TestStolenTokenReplay(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	victim := newClientKey(t)
	tokens := deploy.boundTokens(t, victim, session, "token-1")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	t.Run("with the attacker's own key", func(t *testing.T) {
		attacker := newClientKey(t)
		_, err := deploy.client.DPoPVerify(ctx, tokens.AccessToken,
			attacker.proof(t, "a1", "GET", apiURI, tokens.AccessToken), "GET", apiURI)
		refused(t, "a stolen token presented under another key", err, "dpop_key_mismatch")
	})

	t.Run("with no proof at all", func(t *testing.T) {
		_, err := deploy.client.DPoPVerify(ctx, tokens.AccessToken, "", "GET", apiURI)
		refused(t, "a stolen token presented as a bearer token", err, "dpop_proof_invalid")
	})

	t.Run("with the victim's public key but the attacker's signature", func(t *testing.T) {
		// Copying the victim's `jwk` out of an observed proof is free. What is
		// not free is signing under it.
		attacker := newClientKey(t)
		forged := attacker.signProof(t,
			map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": victim.jwk()},
			map[string]any{"jti": "a2", "htm": "GET", "htu": apiURI,
				"iat": time.Now().Unix(),
				"ath": func() string {
					sum := sha256.Sum256([]byte(tokens.AccessToken))
					return base64.RawURLEncoding.EncodeToString(sum[:])
				}()})
		_, err := deploy.client.DPoPVerify(ctx, tokens.AccessToken, forged, "GET", apiURI)
		refused(t, "a proof carrying the victim's key but another signature",
			err, "dpop_proof_invalid")
	})

	t.Run("with an unsigned proof", func(t *testing.T) {
		// `alg: none` is the oldest JWT attack there is.
		header, _ := json.Marshal(map[string]any{
			"typ": "dpop+jwt", "alg": "none", "jwk": victim.jwk()})
		body, _ := json.Marshal(map[string]any{
			"jti": "a3", "htm": "GET", "htu": apiURI, "iat": time.Now().Unix()})
		unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
			base64.RawURLEncoding.EncodeToString(body) + "."
		_, err := deploy.client.DPoPVerify(ctx, tokens.AccessToken, unsigned, "GET", apiURI)
		refused(t, "an unsigned proof", err, "dpop_proof_invalid")
	})
}

// TestCapturedProofReplay covers the attacker who observed a whole request —
// token and proof together — and tries to repeat it.
func TestCapturedProofReplay(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	victim := newClientKey(t)
	tokens := deploy.boundTokens(t, victim, session, "token-1")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	captured := victim.proof(t, "captured-1", "GET", apiURI, tokens.AccessToken)
	if _, err := deploy.client.DPoPVerify(ctx, tokens.AccessToken, captured,
		"GET", apiURI); err != nil {
		t.Fatalf("the legitimate request failed: %v", err)
	}

	t.Run("verbatim", func(t *testing.T) {
		_, err := deploy.client.DPoPVerify(ctx, tokens.AccessToken, captured, "GET", apiURI)
		refused(t, "a captured proof replayed verbatim", err, "dpop_proof_replayed")
	})

	t.Run("against another endpoint", func(t *testing.T) {
		// A proof good anywhere could be lifted from a read onto a write.
		const write = issuer + "/api/payments"
		_, err := deploy.client.DPoPVerify(ctx, tokens.AccessToken, captured, "POST", write)
		refused(t, "a captured proof aimed at another endpoint", err, "dpop_proof_not_bound")
	})
}

// TestProofCannotBeMintedForAnotherServer.
//
// SESAME sees no HTTP, so it checks a proof against what the host reports.
// This is the one binding check it can make alone: whatever URI the host says
// it served, it has to be one of this deployment's own — so a proof minted for
// somebody else's authorization server is refused even by a host that reported
// it faithfully.
func TestProofCannotBeMintedForAnotherServer(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	key := newClientKey(t)
	tokens := deploy.boundTokens(t, key, session, "token-1")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, foreign := range []string{
		"https://evil.example/api/invoices",
		"https://id.example.evil.test/api/invoices",
		"http://id.example/api/invoices",
		"https://id.example:8443/api/invoices",
	} {
		_, err := deploy.client.DPoPVerify(ctx, tokens.AccessToken,
			key.proof(t, "f-"+foreign[8:12], "GET", foreign, tokens.AccessToken), "GET", foreign)
		refused(t, "a proof for "+foreign, err, "dpop_foreign_origin")
	}
}

// TestBindingCannotBeShedAtRefresh. If a stolen refresh token could be
// exchanged for an unbound bearer token, the binding would be something an
// attacker simply declines to carry forward.
func TestBindingCannotBeShedAtRefresh(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	key := newClientKey(t)
	tokens := deploy.boundTokens(t, key, session, "token-1")
	if tokens.RefreshToken == "" {
		t.Fatal("the flow issued no refresh token")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	refresh := func(proof string) error {
		_, err := deploy.client.TokenExchange(ctx, sesame.TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: tokens.RefreshToken,
			ClientID:     deploy.clientID,
			ClientSecret: deploy.secret,
			DPoPProof:    proof,
			DPoPMethod:   "POST",
			DPoPURI:      tokenURI,
		})
		return err
	}

	refused(t, "a bound refresh token exchanged with no proof", refresh(""), "dpop_required")
	refused(t, "a bound refresh token exchanged under another key",
		refresh(newClientKey(t).proof(t, "r1", "POST", tokenURI, "")), "dpop_key_mismatch")

	if err := refresh(key.proof(t, "r2", "POST", tokenURI, "")); err != nil {
		t.Fatalf("the legitimate refresh failed: %v", err)
	}
}

// TestBearerTokensAreNotSilentlyAcceptedAsBound. A verification surface that
// reported any bearer token active when handed a valid proof would make the
// binding decorative for every client that skipped it.
func TestBearerTokensAreNotSilentlyAcceptedAsBound(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	key := newClientKey(t)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	response := deploy.authorize(t, session)
	bearer, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code))
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	if bearer.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", bearer.TokenType)
	}

	verification, err := deploy.client.DPoPVerify(ctx, bearer.AccessToken,
		key.proof(t, "b1", "GET", apiURI, bearer.AccessToken), "GET", apiURI)
	if err != nil {
		t.Fatalf("DPoPVerify() error = %v", err)
	}
	if verification.Active {
		t.Fatal("an unbound bearer token verified as key-bound")
	}
}

// TestRevocationOutranksKeyPossession. Key binding answers "is this the right
// holder"; it must never answer "is this grant still alive".
func TestRevocationOutranksKeyPossession(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	key := newClientKey(t)
	tokens := deploy.boundTokens(t, key, session, "token-1")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := deploy.client.SessionRevoke(ctx, session.SessionID, "incident"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	verification, err := deploy.client.DPoPVerify(ctx, tokens.AccessToken,
		key.proof(t, "v1", "GET", apiURI, tokens.AccessToken), "GET", apiURI)
	if err != nil {
		t.Fatalf("DPoPVerify() error = %v", err)
	}
	if verification.Active {
		t.Fatal("a revoked session still verified under a proved key")
	}
}
