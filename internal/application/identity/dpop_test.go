package identity

import (
	"context"
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

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

const (
	dpopTokenURI = flowIssuer + "/oauth/token"
	dpopAPIURI   = flowIssuer + "/api/invoices"
)

// dpopKey is a test client holding a DPoP key.
type dpopKey struct {
	private     *ecdsa.PrivateKey
	publicPoint []byte
}

func newDPoPKey(t *testing.T) *dpopKey {
	t.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	return &dpopKey{private: private, publicPoint: mustPublicPoint(t, private)}
}

func mustPublicPoint(t testing.TB, private *ecdsa.PrivateKey) []byte {
	t.Helper()

	point, err := private.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	return point
}

func (d *dpopKey) jwk() map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(d.publicPoint[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(d.publicPoint[33:]),
	}
}

func (d *dpopKey) thumbprint() string {
	key := d.jwk()
	return oidcdomain.JWKThumbprint(key["crv"].(string), key["kty"].(string),
		key["x"].(string), key["y"].(string))
}

// proof mints one proof. accessToken empty omits `ath`, which is what a proof
// at the token endpoint looks like.
func (d *dpopKey) proof(t *testing.T, id, method, uri, accessToken string, now time.Time) string {
	t.Helper()

	body := map[string]any{"jti": id, "htm": method, "htu": uri, "iat": now.Unix()}
	if accessToken != "" {
		body["ath"] = oidcdomain.AccessTokenHash(accessToken)
	}
	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal proof segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	input := encode(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256", "jwk": d.jwk(),
	}) + "." + encode(body)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, d.private, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// offlineClientFixture registers a client that may ask for offline_access, so
// a refresh token exists to test the binding on.
func offlineClientFixture(t *testing.T) *flowFixture {
	t.Helper()

	fixture := newFlowFixture(t)
	registered, err := fixture.service.ClientRegister(context.Background(), fixture.tenantID,
		"offline-dpop", oidcdomain.TypeConfidential, []string{flowRedirectURI},
		[]string{"profile", oidcdomain.ScopeOfflineAccess}, oidcdomain.AudienceFirstParty,
		nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	fixture.clientID = registered.Client.ID
	fixture.secret = registered.Secret
	return fixture
}

// boundTokens runs one authorization code flow to a key-bound token set.
func (f *flowFixture) boundTokens(t *testing.T, key *dpopKey, proofID string,
	scopes ...string) TokenResponse {
	t.Helper()

	ctx := context.Background()
	if len(scopes) == 0 {
		scopes = []string{"profile"}
	}
	started, err := f.service.AuthorizationStart(ctx, AuthorizationRequest{
		ClientID:            f.clientID,
		RedirectURI:         flowRedirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              scopes,
		CodeChallenge:       flowChallenge(),
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}, "test")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	authorization, err := f.service.AuthorizationComplete(ctx, started.InteractionID,
		started.Secret, f.sessionID, f.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	request := f.tokenRequest(authorization.Code)
	request.DPoPProof = key.proof(t, proofID, "POST", dpopTokenURI, "", f.now)
	request.DPoPMethod = "POST"
	request.DPoPURI = dpopTokenURI

	tokens, err := f.service.TokenExchange(ctx, request, "test")
	if err != nil {
		t.Fatalf("TokenExchange() with a proof error = %v", err)
	}
	return tokens
}

// TestATokenIsBoundToTheKeyThatProvedPossession is the happy path, and it
// checks the claim rather than only that issuance succeeded: a `cnf.jkt` that
// never reached the token would leave the whole scheme decorative.
func TestATokenIsBoundToTheKeyThatProvedPossession(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	key := newDPoPKey(t)
	tokens := fixture.boundTokens(t, key, "proof-1")

	if tokens.TokenType != oidcdomain.TokenTypeDPoP {
		t.Fatalf("token_type = %q, want %q; a client would send it as a bearer token",
			tokens.TokenType, oidcdomain.TokenTypeDPoP)
	}
	_, body, err := fixture.signingKey.Verify(tokens.AccessToken, flowIssuer,
		fixture.clientID, fixture.now)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	confirmation, ok := body["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("the access token carries no cnf claim: %v", body)
	}
	if confirmation["jkt"] != key.thumbprint() {
		t.Fatalf("cnf.jkt = %v, want %q", confirmation["jkt"], key.thumbprint())
	}
}

// TestATokenIssuedWithoutAProofIsAnOrdinaryBearerToken. DPoP is per request:
// a client that does not use it must not be broken by its existence.
func TestATokenIssuedWithoutAProofIsAnOrdinaryBearerToken(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	started := fixture.authorize(t)
	authorization, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID,
		started.Secret, fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	tokens, err := fixture.service.TokenExchange(ctx,
		fixture.tokenRequest(authorization.Code), "test")
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	if tokens.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", tokens.TokenType)
	}
	_, body, err := fixture.signingKey.Verify(tokens.AccessToken, flowIssuer,
		fixture.clientID, fixture.now)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if _, bound := body["cnf"]; bound {
		t.Fatal("an unbound token carries a confirmation claim")
	}
}

// TestAProofIsSpentOnce is the replay store's whole job.
func TestAProofIsSpentOnce(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	key := newDPoPKey(t)
	tokens := fixture.boundTokens(t, key, "proof-1")

	proof := key.proof(t, "api-1", "GET", dpopAPIURI, tokens.AccessToken, fixture.now)
	if _, err := fixture.service.DPoPVerify(context.Background(), tokens.AccessToken,
		proof, "GET", dpopAPIURI, "test"); err != nil {
		t.Fatalf("DPoPVerify() error = %v", err)
	}
	if _, err := fixture.service.DPoPVerify(context.Background(), tokens.AccessToken,
		proof, "GET", dpopAPIURI, "test"); !errors.Is(err, ErrDPoPProofReplayed) {
		t.Fatalf("a replayed proof: err = %v, want ErrDPoPProofReplayed", err)
	}
}

// TestProofIdentifiersAreScopedToTheirKey. `jti` is unique per client, not
// globally, so treating one client's identifier as a replay of another's would
// refuse a legitimate request for no gain.
func TestProofIdentifiersAreScopedToTheirKey(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	first, second := newDPoPKey(t), newDPoPKey(t)
	firstTokens := fixture.boundTokens(t, first, "shared-id")
	secondTokens := fixture.boundTokens(t, second, "shared-id")

	ctx := context.Background()
	if _, err := fixture.service.DPoPVerify(ctx, firstTokens.AccessToken,
		first.proof(t, "api-1", "GET", dpopAPIURI, firstTokens.AccessToken, fixture.now),
		"GET", dpopAPIURI, "test"); err != nil {
		t.Fatalf("first client: %v", err)
	}
	if _, err := fixture.service.DPoPVerify(ctx, secondTokens.AccessToken,
		second.proof(t, "api-1", "GET", dpopAPIURI, secondTokens.AccessToken, fixture.now),
		"GET", dpopAPIURI, "test"); err != nil {
		t.Fatalf("a second client's identical jti was refused as a replay: %v", err)
	}
}

// TestAStolenTokenIsUselessWithoutItsKey is the property the whole scheme
// exists for. The attacker below has the access token and can mint perfectly
// valid proofs — just not with the right key.
func TestAStolenTokenIsUselessWithoutItsKey(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	victim := newDPoPKey(t)
	tokens := fixture.boundTokens(t, victim, "proof-1")

	attacker := newDPoPKey(t)
	if _, err := fixture.service.DPoPVerify(context.Background(), tokens.AccessToken,
		attacker.proof(t, "api-1", "GET", dpopAPIURI, tokens.AccessToken, fixture.now),
		"GET", dpopAPIURI, "test"); !errors.Is(err, oidcdomain.ErrDPoPKeyMismatch) {
		t.Fatalf("a stolen token verified under another key: err = %v", err)
	}
}

// TestVerificationRefusesWhatItCannotVouchFor.
func TestVerificationRefusesWhatItCannotVouchFor(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	key := newDPoPKey(t)
	tokens := fixture.boundTokens(t, key, "proof-1")
	ctx := context.Background()

	t.Run("a proof for another endpoint", func(t *testing.T) {
		if _, err := fixture.service.DPoPVerify(ctx, tokens.AccessToken,
			key.proof(t, "api-1", "GET", flowIssuer+"/api/other", tokens.AccessToken, fixture.now),
			"GET", dpopAPIURI, "test"); !errors.Is(err, oidcdomain.ErrDPoPProofNotBound) {
			t.Fatalf("err = %v, want ErrDPoPProofNotBound", err)
		}
	})

	t.Run("a proof for another authorization server", func(t *testing.T) {
		// The one binding check the engine can make without trusting the host.
		const foreign = "https://evil.example/api/invoices"
		if _, err := fixture.service.DPoPVerify(ctx, tokens.AccessToken,
			key.proof(t, "api-2", "GET", foreign, tokens.AccessToken, fixture.now),
			"GET", foreign, "test"); !errors.Is(err, ErrDPoPProofForeignOrigin) {
			t.Fatalf("err = %v, want ErrDPoPProofForeignOrigin", err)
		}
	})

	t.Run("a proof with no ath", func(t *testing.T) {
		if _, err := fixture.service.DPoPVerify(ctx, tokens.AccessToken,
			key.proof(t, "api-3", "GET", dpopAPIURI, "", fixture.now),
			"GET", dpopAPIURI, "test"); !errors.Is(err, oidcdomain.ErrDPoPProofNotBound) {
			t.Fatalf("err = %v, want ErrDPoPProofNotBound", err)
		}
	})

	t.Run("an unbound bearer token", func(t *testing.T) {
		// Presenting any bearer token with a valid proof must not be reported
		// as a verified pair.
		started := fixture.authorize(t)
		authorization, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID,
			started.Secret, fixture.sessionID, fixture.sessionKey, "test")
		if err != nil {
			t.Fatalf("AuthorizationComplete() error = %v", err)
		}
		bearer, err := fixture.service.TokenExchange(ctx,
			fixture.tokenRequest(authorization.Code), "test")
		if err != nil {
			t.Fatalf("TokenExchange() error = %v", err)
		}
		verified, err := fixture.service.DPoPVerify(ctx, bearer.AccessToken,
			key.proof(t, "api-4", "GET", dpopAPIURI, bearer.AccessToken, fixture.now),
			"GET", dpopAPIURI, "test")
		if err != nil {
			t.Fatalf("DPoPVerify() error = %v", err)
		}
		if verified.Active {
			t.Fatal("an unbound bearer token verified as a key-bound one")
		}
	})

	t.Run("a garbage token", func(t *testing.T) {
		verified, err := fixture.service.DPoPVerify(ctx, "not.a.token",
			key.proof(t, "api-5", "GET", dpopAPIURI, "not.a.token", fixture.now),
			"GET", dpopAPIURI, "test")
		if err != nil {
			t.Fatalf("DPoPVerify() error = %v", err)
		}
		if verified.Active {
			t.Fatal("a garbage token verified")
		}
	})
}

// TestAProofIsSpentEvenWhenTheTokenFails.
//
// A proof rejected without being spent could be retried against a different
// token until one stuck, which is the offline search the replay store exists
// to prevent.
func TestAProofIsSpentEvenWhenTheTokenFails(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	key := newDPoPKey(t)
	tokens := fixture.boundTokens(t, key, "proof-1")
	ctx := context.Background()

	_ = tokens
	// The token is unverifiable, so this call reports inactive rather than
	// erroring — but the proof it carried is still gone.
	proof := key.proof(t, "api-1", "GET", dpopAPIURI, "not.a.token", fixture.now)
	verified, err := fixture.service.DPoPVerify(ctx, "not.a.token", proof,
		"GET", dpopAPIURI, "test")
	if err != nil {
		t.Fatalf("DPoPVerify() error = %v", err)
	}
	if verified.Active {
		t.Fatal("a garbage token verified")
	}
	if _, err := fixture.service.DPoPVerify(ctx, "not.a.token", proof,
		"GET", dpopAPIURI, "test"); !errors.Is(err, ErrDPoPProofReplayed) {
		t.Fatalf("a proof rejected on the token was not spent: err = %v", err)
	}
}

// TestRevocationStillBitesAKeyBoundToken. Key binding is orthogonal to
// revocation, not a substitute for it.
func TestRevocationStillBitesAKeyBoundToken(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	key := newDPoPKey(t)
	tokens := fixture.boundTokens(t, key, "proof-1")
	ctx := context.Background()

	if err := fixture.service.SessionRevoke(ctx, fixture.sessionID, "logout", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	verified, err := fixture.service.DPoPVerify(ctx, tokens.AccessToken,
		key.proof(t, "api-1", "GET", dpopAPIURI, tokens.AccessToken, fixture.now),
		"GET", dpopAPIURI, "test")
	if err != nil {
		t.Fatalf("DPoPVerify() error = %v", err)
	}
	if verified.Active {
		t.Fatal("a revoked session still verified a key-bound token")
	}
}

// TestABoundRefreshTokenStaysBound is RFC 9449 section 7.1.
//
// Without this a stolen refresh token could be exchanged for an unbound bearer
// token, and the binding would be something an attacker simply declines to
// carry forward.
func TestABoundRefreshTokenStaysBound(t *testing.T) {
	t.Parallel()

	fixture := offlineClientFixture(t)
	key := newDPoPKey(t)
	tokens := fixture.boundTokens(t, key, "proof-1", "profile", oidcdomain.ScopeOfflineAccess)
	if tokens.RefreshToken == "" {
		t.Fatal("offline_access issued no refresh token")
	}
	ctx := context.Background()

	refresh := func(proof string) (TokenResponse, error) {
		return fixture.service.TokenExchange(ctx, TokenRequest{
			GrantType:    oidcdomain.GrantTypeRefreshToken,
			RefreshToken: tokens.RefreshToken,
			ClientID:     fixture.clientID,
			ClientSecret: fixture.secret,
			DPoPProof:    proof,
			DPoPMethod:   "POST",
			DPoPURI:      dpopTokenURI,
		}, "test")
	}

	t.Run("without a proof", func(t *testing.T) {
		if _, err := refresh(""); !errors.Is(err, ErrDPoPRequired) {
			t.Fatalf("err = %v, want ErrDPoPRequired", err)
		}
	})

	t.Run("with another key", func(t *testing.T) {
		attacker := newDPoPKey(t)
		if _, err := refresh(attacker.proof(t, "r-1", "POST", dpopTokenURI, "",
			fixture.now)); !errors.Is(err, oidcdomain.ErrDPoPKeyMismatch) {
			t.Fatalf("err = %v, want ErrDPoPKeyMismatch", err)
		}
	})

	t.Run("with the right key", func(t *testing.T) {
		rotated, err := refresh(key.proof(t, "r-2", "POST", dpopTokenURI, "", fixture.now))
		if err != nil {
			t.Fatalf("refresh with the bound key error = %v", err)
		}
		if rotated.TokenType != oidcdomain.TokenTypeDPoP {
			t.Fatalf("a rotated token came back as %q", rotated.TokenType)
		}
		// The successor is bound to the same key, so the binding travels down
		// the family rather than stopping at the first rotation.
		_, body, err := fixture.signingKey.Verify(rotated.AccessToken, flowIssuer,
			fixture.clientID, fixture.now)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		confirmation, _ := body["cnf"].(map[string]any)
		if confirmation["jkt"] != key.thumbprint() {
			t.Fatalf("the rotated token dropped its binding: %v", body["cnf"])
		}
	})
}

// TestIntrospectionReportsTheBinding: a resource server told a token is bound
// but nothing about to what cannot enforce the binding.
func TestIntrospectionReportsTheBinding(t *testing.T) {
	t.Parallel()

	fixture := offlineClientFixture(t)
	key := newDPoPKey(t)
	tokens := fixture.boundTokens(t, key, "proof-1", "profile", oidcdomain.ScopeOfflineAccess)

	request := TokenRequest{ClientID: fixture.clientID, ClientSecret: fixture.secret}
	access, err := fixture.service.Introspect(request, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if !access.Active || access.Thumbprint != key.thumbprint() {
		t.Fatalf("access introspection = %#v", access)
	}
	refresh, err := fixture.service.Introspect(request, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if !refresh.Active || refresh.Thumbprint != key.thumbprint() {
		t.Fatalf("refresh introspection = %#v", refresh)
	}
}

// TestSpentProofsDoNotAccumulate. The replay store is the busiest projection
// in the engine — one entry per request — so a leak here is not a slow one.
func TestSpentProofsDoNotAccumulate(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	key := newDPoPKey(t)
	tokens := fixture.boundTokens(t, key, "proof-1")
	ctx := context.Background()

	for _, id := range []string{"api-1", "api-2", "api-3"} {
		if _, err := fixture.service.DPoPVerify(ctx, tokens.AccessToken,
			key.proof(t, id, "GET", dpopAPIURI, tokens.AccessToken, fixture.now),
			"GET", dpopAPIURI, "test"); err != nil {
			t.Fatalf("DPoPVerify() error = %v", err)
		}
	}
	fixture.service.mu.Lock()
	live := len(fixture.service.dpopProofs)
	fixture.service.mu.Unlock()
	// Three here plus the one spent issuing the token.
	if live != 4 {
		t.Fatalf("projection holds %d spent proofs, want 4", live)
	}

	// A proof past its window is refused on its own iat, so its identifier has
	// nothing left to say.
	fixture.now = fixture.now.Add(oidcdomain.DPoPProofLifetime + time.Second)
	if _, err := fixture.service.DPoPVerify(ctx, tokens.AccessToken,
		key.proof(t, "api-4", "GET", dpopAPIURI, tokens.AccessToken, fixture.now),
		"GET", dpopAPIURI, "test"); err != nil {
		t.Fatalf("DPoPVerify() error = %v", err)
	}
	fixture.service.mu.Lock()
	remaining := len(fixture.service.dpopProofs)
	exported := len(fixture.service.exportDPoPProofsLocked())
	fixture.service.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("spent proofs past their window were kept: %d, want 1", remaining)
	}
	if exported != 1 {
		t.Fatalf("spent proofs past their window reached a snapshot: %d, want 1", exported)
	}
}

// TestSpentProofsSurviveARestart: the replay claim has to be durable, or
// restarting the engine makes every observed proof usable again.
//
// The durability is the ledger's. Spending a proof deliberately does not write
// a snapshot: a snapshot is a full state export, and taking one per proof would
// mean serializing the entire engine on every API request. A snapshot bounds
// how far replay has to go; the events after it are replayed, which is what
// this rebuild exercises.
func TestSpentProofsSurviveARestart(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	key := newDPoPKey(t)
	tokens := fixture.boundTokens(t, key, "proof-1")
	proof := key.proof(t, "api-1", "GET", dpopAPIURI, tokens.AccessToken, fixture.now)
	ctx := context.Background()
	if _, err := fixture.service.DPoPVerify(ctx, tokens.AccessToken, proof,
		"GET", dpopAPIURI, "test"); err != nil {
		t.Fatalf("DPoPVerify() error = %v", err)
	}

	restored, err := New(fixture.ledger, fixture.ledger.events)
	if err != nil {
		t.Fatalf("New() from the ledger error = %v", err)
	}
	restored.UseIssuer(flowIssuer)
	restored.UseSigningKey(fixture.signingKey)
	restored.UseClock(func() time.Time { return fixture.now })

	if _, err := restored.DPoPVerify(ctx, tokens.AccessToken, proof,
		"GET", dpopAPIURI, "test"); !errors.Is(err, ErrDPoPProofReplayed) {
		t.Fatalf("a restart forgot a spent proof: err = %v", err)
	}

	// A snapshot has to carry them too, since it is what bounds replay: one
	// that dropped the store would leave a window of proofs nothing refuses.
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)
	issuance := key.proof(t, "api-2", "GET", dpopAPIURI, tokens.AccessToken, fixture.now)
	if _, err := fixture.service.DPoPVerify(ctx, tokens.AccessToken, issuance,
		"GET", dpopAPIURI, "test"); err != nil {
		t.Fatalf("DPoPVerify() error = %v", err)
	}
	// Any snapshotting command exports the store as it now stands.
	if _, err := fixture.service.DeviceAuthorizationStart(ctx, fixture.clientID,
		[]string{"profile"}, "test"); err != nil {
		t.Fatalf("DeviceAuthorizationStart() error = %v", err)
	}
	fromSnapshot, err := NewFromSnapshot(&memoryLedger{},
		snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	fromSnapshot.UseIssuer(flowIssuer)
	fromSnapshot.UseSigningKey(fixture.signingKey)
	fromSnapshot.UseClock(func() time.Time { return fixture.now })
	if _, err := fromSnapshot.DPoPVerify(ctx, tokens.AccessToken, issuance,
		"GET", dpopAPIURI, "test"); !errors.Is(err, ErrDPoPProofReplayed) {
		t.Fatalf("a snapshot dropped the replay store: err = %v", err)
	}
}

// TestAMalformedProofNeverReachesIssuance: a token endpoint that ignored an
// unusable proof would issue an unbound token to a client that believes it
// holds a bound one.
func TestAMalformedProofNeverReachesIssuance(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	key := newDPoPKey(t)
	ctx := context.Background()

	valid := key.proof(t, "p", "POST", dpopTokenURI, "", fixture.now)
	for name, proof := range map[string]string{
		"not a JWS": "garbage",
		"a bad signature": strings.Join(strings.Split(valid, ".")[:2], ".") +
			".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"a proof for another method": key.proof(t, "p2", "GET", dpopTokenURI, "", fixture.now),
		"a proof for another URI": key.proof(t, "p3", "POST",
			"https://evil.example/token", "", fixture.now),
	} {
		t.Run(name, func(t *testing.T) {
			started := fixture.authorize(t)
			authorization, err := fixture.service.AuthorizationComplete(ctx,
				started.InteractionID, started.Secret, fixture.sessionID, fixture.sessionKey, "test")
			if err != nil {
				t.Fatalf("AuthorizationComplete() error = %v", err)
			}
			request := fixture.tokenRequest(authorization.Code)
			request.DPoPProof = proof
			request.DPoPMethod = "POST"
			request.DPoPURI = dpopTokenURI
			if _, err := fixture.service.TokenExchange(ctx, request, "test"); err == nil {
				t.Fatalf("the token endpoint issued tokens with %s", name)
			}
		})
	}
}
