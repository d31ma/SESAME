package fylo_test

import (
	"context"
	"crypto/rand"
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
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

// TestRealFYLOPushedRequestSurvivesRestart proves against a real FYLO runtime
// that the single-use claim on a pushed reference is durable.
//
// The claim is the whole security of PAR's second half. A reference travels in
// the browser — it is in history, in referrers, possibly in a proxy log — and
// what makes that harmless is that it can be redeemed exactly once. If a
// restart forgot which references had been spent, every reference an attacker
// had ever observed would become live again, which is worse than not having
// pushed the request at all.
//
// So two things have to replay: an unspent reference is still redeemable, and
// a spent one is still refused.
func TestRealFYLOPushedRequestSurvivesRestart(t *testing.T) {
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
	root, err := os.MkdirTemp("", "sesame-pushed-*")
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

	const issuer = "https://id.example.com"
	now := time.Unix(1_700_000_000, 0).UTC()

	secretsKey := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	if _, err := rand.Read(secretsKey); err != nil {
		t.Fatalf("generate secrets key: %v", err)
	}
	signing, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}

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
	tenant, err := service.Bootstrap(ctx, "par-co", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	const redirectURI = "https://app.example/cb"
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "pushing-app",
		oidcdomain.TypeConfidential, []string{redirectURI},
		[]string{"profile"}, oidcdomain.AudienceFirstParty, nil, "test:integration")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	push := func(service *identityapp.Service) identityapp.PushedAuthorizationRequest {
		t.Helper()
		pushed, err := service.PushedAuthorizationStart(ctx, identityapp.AuthorizationRequest{
			ClientID:            registered.Client.ID,
			RedirectURI:         redirectURI,
			ResponseType:        oidcdomain.ResponseTypeCode,
			Scopes:              []string{"profile"},
			State:               "client-state",
			Nonce:               "client-nonce",
			CodeChallenge:       pushedChallenge,
			CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
		}, registered.Secret, "test:integration")
		if err != nil {
			t.Fatalf("PushedAuthorizationStart() error = %v", err)
		}
		return pushed
	}

	// One reference is spent before the restart; a second is left live, so the
	// restart has to remember both facts and not merely one of them.
	spent := push(service)
	live := push(service)
	if _, err := service.AuthorizationStart(ctx, identityapp.AuthorizationRequest{
		ClientID: registered.Client.ID, RequestURI: spent.RequestURI,
	}, "test:integration"); err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// ---- restart ----
	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	if _, err := replayed.AuthorizationStart(ctx, identityapp.AuthorizationRequest{
		ClientID: registered.Client.ID, RequestURI: spent.RequestURI,
	}, "test:integration"); !errors.Is(err, identityapp.ErrRequestURINotFound) {
		t.Fatalf("a restart forgot a spent request_uri: err = %v", err)
	}

	started, err := replayed.AuthorizationStart(ctx, identityapp.AuthorizationRequest{
		ClientID: registered.Client.ID, RequestURI: live.RequestURI,
	}, "test:integration")
	if err != nil {
		t.Fatalf("a restart stranded a live request_uri: %v", err)
	}
	// The request came back intact, not merely acknowledged: what the browser
	// carried was one opaque string, so everything below was replayed from the
	// ledger.
	if len(started.Scopes) == 0 || started.Scopes[0] != "openid" {
		t.Fatalf("restored scopes = %v", started.Scopes)
	}
	if started.ClientName != "pushing-app" {
		t.Fatalf("restored interaction = %#v", started)
	}

	// And it is single use on the far side of the restart too.
	if _, err := replayed.AuthorizationStart(ctx, identityapp.AuthorizationRequest{
		ClientID: registered.Client.ID, RequestURI: live.RequestURI,
	}, "test:integration"); !errors.Is(err, identityapp.ErrRequestURINotFound) {
		t.Fatalf("a restored request_uri was redeemable twice: err = %v", err)
	}
}

// pushedChallenge is the S256 challenge for a fixed verifier.
const pushedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
