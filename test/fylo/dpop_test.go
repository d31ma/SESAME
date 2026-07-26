package fylo_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

// fyloDPoPKey mints proofs the way a client would.
type fyloDPoPKey struct{ private *ecdsa.PrivateKey }

func (f *fyloDPoPKey) proof(t *testing.T, id, method, uri, accessToken string, now time.Time) string {
	t.Helper()

	body := map[string]any{"jti": id, "htm": method, "htu": uri, "iat": now.Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		body["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal proof segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	input := encode(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]any{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(
				f.private.PublicKey.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(
				f.private.PublicKey.Y.FillBytes(make([]byte, 32))),
		},
	}) + "." + encode(body)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, f.private, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// TestRealFYLODPoPBindingSurvivesRestart proves against a real FYLO runtime
// that key binding and proof replay both replay.
//
// Two claims have to survive, and they fail in opposite directions. A binding
// that was forgotten would silently downgrade a key-bound grant to a bearer
// one — every token an attacker had ever captured becomes usable. A spent
// proof that was forgotten would make every proof an attacker had ever
// observed replayable for its window. Restarting is not an exotic event here:
// a refresh token lives thirty days and outlives any number of restarts.
func TestRealFYLODPoPBindingSurvivesRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}
	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	root, err := os.MkdirTemp("", "sesame-dpop-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	const (
		issuer      = "https://id.example.com"
		tokenURI    = issuer + "/oauth/token"
		apiURI      = issuer + "/api/invoices"
		redirectURI = "https://app.example/cb"
		password    = "correct horse battery staple"
		verifier    = "sesame-fylo-dpop-verifier-0123456789-abcdefgh"
	)
	now := time.Unix(1_700_000_000, 0).UTC()
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])

	secretsKey := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	if _, err := rand.Read(secretsKey); err != nil {
		t.Fatalf("generate secrets key: %v", err)
	}
	signing, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	key := &fyloDPoPKey{private: private}

	open := func() (*fyloadapter.Client, *identityapp.Service) {
		t.Helper()
		client, err := fyloadapter.Start(ctx, config)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		ledger, events, err := securityledger.Open(ctx, client)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		service, err := identityapp.New(ledger, events)
		if err != nil {
			t.Fatalf("identity.New() error = %v", err)
		}
		service.UseSecretsKey(secretsKey)
		service.UseSigningKey(signing)
		service.UseIssuer(issuer)
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "dpop-co", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "holder@example.com"}
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID,
		principaldomain.KindHuman, identifier, "test:integration")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, password, "test:integration"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "bound-app",
		oidcdomain.TypeConfidential, []string{redirectURI},
		[]string{"profile", oidcdomain.ScopeOfflineAccess},
		oidcdomain.AudienceFirstParty, nil, "test:integration")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	begun, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test:integration")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID,
		password, "test:integration"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := service.AuthenticationComplete(ctx, begun.TransactionID,
		time.Hour, "test:integration")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	started, err := service.AuthorizationStart(ctx, identityapp.AuthorizationRequest{
		ClientID:            registered.Client.ID,
		RedirectURI:         redirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{"profile", oidcdomain.ScopeOfflineAccess},
		CodeChallenge:       challenge,
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}, "test:integration")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	authorization, err := service.AuthorizationComplete(ctx, started.InteractionID,
		started.Secret, session.SessionID, session.Secret, "test:integration")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	tokens, err := service.TokenExchange(ctx, identityapp.TokenRequest{
		GrantType:    oidcdomain.GrantTypeAuthorizationCode,
		Code:         authorization.Code,
		RedirectURI:  redirectURI,
		ClientID:     registered.Client.ID,
		ClientSecret: registered.Secret,
		CodeVerifier: verifier,
		DPoPProof:    key.proof(t, "token-1", "POST", tokenURI, "", now),
		DPoPMethod:   "POST",
		DPoPURI:      tokenURI,
	}, "test:integration")
	if err != nil {
		t.Fatalf("TokenExchange() with a proof error = %v", err)
	}
	if tokens.TokenType != oidcdomain.TokenTypeDPoP || tokens.RefreshToken == "" {
		t.Fatalf("tokens = %#v", tokens)
	}

	// One proof is spent before the restart, so the replay claim has something
	// to forget.
	spent := key.proof(t, "api-1", "GET", apiURI, tokens.AccessToken, now)
	if _, err := service.DPoPVerify(ctx, tokens.AccessToken, spent, "GET", apiURI,
		"test:integration"); err != nil {
		t.Fatalf("DPoPVerify() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// ---- restart ----
	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	// The spent proof is still spent.
	if _, err := replayed.DPoPVerify(ctx, tokens.AccessToken, spent, "GET", apiURI,
		"test:integration"); !errors.Is(err, identityapp.ErrDPoPProofReplayed) {
		t.Fatalf("a restart forgot a spent proof: err = %v", err)
	}

	// A fresh proof under the right key still works, so the restart refused a
	// replay rather than refusing everything.
	verification, err := replayed.DPoPVerify(ctx, tokens.AccessToken,
		key.proof(t, "api-2", "GET", apiURI, tokens.AccessToken, now),
		"GET", apiURI, "test:integration")
	if err != nil {
		t.Fatalf("DPoPVerify() after restart error = %v", err)
	}
	if !verification.Active {
		t.Fatal("a restored key-bound token verified as inactive")
	}

	// The refresh token is still bound: exchanging it without a proof is
	// refused, and exchanging it under another key is refused.
	refresh := func(service *identityapp.Service, proof string) (identityapp.TokenResponse, error) {
		return service.TokenExchange(ctx, identityapp.TokenRequest{
			GrantType:    oidcdomain.GrantTypeRefreshToken,
			RefreshToken: tokens.RefreshToken,
			ClientID:     registered.Client.ID,
			ClientSecret: registered.Secret,
			DPoPProof:    proof,
			DPoPMethod:   "POST",
			DPoPURI:      tokenURI,
		}, "test:integration")
	}
	if _, err := refresh(replayed, ""); !errors.Is(err, identityapp.ErrDPoPRequired) {
		t.Fatalf("a restart dropped a refresh token's binding: err = %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	attacker := &fyloDPoPKey{private: other}
	if _, err := refresh(replayed,
		attacker.proof(t, "r-1", "POST", tokenURI, "", now)); !errors.Is(err,
		oidcdomain.ErrDPoPKeyMismatch) {
		t.Fatalf("a restored refresh token accepted another key: err = %v", err)
	}

	// And the legitimate holder can still rotate, with the binding intact on
	// the successor.
	rotated, err := refresh(replayed, key.proof(t, "r-2", "POST", tokenURI, "", now))
	if err != nil {
		t.Fatalf("the legitimate refresh failed after restart: %v", err)
	}
	if rotated.TokenType != oidcdomain.TokenTypeDPoP {
		t.Fatalf("a rotated token came back as %q; the binding stopped at the "+
			"first rotation", rotated.TokenType)
	}
}
