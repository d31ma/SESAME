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
	"github.com/d31ma/sesame/internal/domain/saml/samltest"
)

// TestRealFYLOSAMLSurvivesRestart proves against a real FYLO runtime that
// inbound SAML state is durable across a process restart.
//
// Four things are at stake and each fails differently if a projection is
// wrong. A provider that does not replay means every SAML login refuses after
// a restart. A certificate that does not replay means signatures stop
// verifying. A subject link that does not replay means a returning user is
// treated as a stranger and, under verified-email linking, gets a *second*
// principal. And a spent-assertion claim that does not replay is the worst of
// the four: it makes a restart the moment every captured assertion inside its
// validity window becomes replayable again.
//
// Unlike inbound OIDC, an in-flight SAML login must come back fully usable.
// It holds no sealed secret — the request identifier travels in the
// AuthnRequest, and its unguessability rather than its confidentiality is
// what binds an assertion to the attempt — so refusing it after a restart
// would be an outage with no security benefit.
func TestRealFYLOSAMLSurvivesRestart(t *testing.T) {
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
	root, err := os.MkdirTemp("", "sesame-saml-*")
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
		deploymentIssuer = "https://sesame.example"
		entityID         = "https://idp.example.com/metadata"
		ssoURL           = "https://idp.example.com/sso"
		consumerURL      = "https://app.example/saml/acs"
	)
	now := time.Unix(1_700_000_000, 0).UTC()

	secretsKey := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	if _, err := rand.Read(secretsKey); err != nil {
		t.Fatalf("generate secrets key: %v", err)
	}
	signer, err := samltest.NewSigner("idp.example.com")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
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
		service.UseIssuer(deploymentIssuer)
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	assertion := func(requestID, id string) samltest.Assertion {
		return samltest.Assertion{
			ID:           id,
			Issuer:       entityID,
			Subject:      "alice@example.com",
			Audience:     deploymentIssuer,
			Recipient:    consumerURL,
			RequestID:    requestID,
			NotBefore:    now.Add(-time.Minute),
			NotOnOrAfter: now.Add(5 * time.Minute),
		}
	}
	sign := func(a samltest.Assertion) []byte {
		t.Helper()
		document, err := signer.Sign(a.Document())
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		return []byte(document)
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	provider, err := service.SAMLProviderRegister(ctx, tenant.Tenant.ID, "Corp SSO",
		entityID, ssoURL, []string{signer.PEM}, "email", "verified_email",
		"test:integration")
	if err != nil {
		t.Fatalf("SAMLProviderRegister() error = %v", err)
	}

	// One login is completed, which creates the subject link and spends an
	// assertion; a second is left in flight, so the restart has both states.
	completedLogin, err := service.SAMLLoginStart(ctx, tenant.Tenant.ID, provider.ID,
		consumerURL, "test:integration")
	if err != nil {
		t.Fatalf("SAMLLoginStart() error = %v", err)
	}
	spent := assertion(completedLogin.RequestID, "_spent-assertion")
	first, err := service.SAMLLoginComplete(ctx, tenant.Tenant.ID, completedLogin.LoginID,
		sign(spent), "test:integration")
	if err != nil {
		t.Fatalf("SAMLLoginComplete() error = %v", err)
	}
	if !first.Provisioned {
		t.Fatal("a first-time SAML user was not provisioned")
	}
	inFlight, err := service.SAMLLoginStart(ctx, tenant.Tenant.ID, provider.ID,
		consumerURL, "test:integration")
	if err != nil {
		t.Fatalf("SAMLLoginStart() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// ---- restart ----
	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	view, err := replayed.SAMLProviderGet(tenant.Tenant.ID, provider.ID)
	if err != nil {
		t.Fatalf("SAMLProviderGet() after restart error = %v", err)
	}
	if view.EntityID != entityID || len(view.Certificates) != 1 {
		t.Fatalf("provider after restart = %#v", view)
	}

	// The spent assertion is still spent. This is the claim that matters
	// most: an attacker holding a captured assertion gains nothing from
	// waiting for a restart.
	afterRestart, err := replayed.SAMLLoginStart(ctx, tenant.Tenant.ID, provider.ID,
		consumerURL, "test:integration")
	if err != nil {
		t.Fatalf("SAMLLoginStart() after restart error = %v", err)
	}
	replayedAssertion := spent
	replayedAssertion.RequestID = afterRestart.RequestID
	if _, err := replayed.SAMLLoginComplete(ctx, tenant.Tenant.ID, afterRestart.LoginID,
		sign(replayedAssertion), "test:integration"); !errors.Is(
		err, identityapp.ErrSAMLAssertionRejected) {
		t.Fatalf("a restart forgot a spent assertion: err = %v", err)
	}

	// The subject link replays: the same external user is the same principal,
	// and is not provisioned a second time.
	returning, err := replayed.SAMLLoginStart(ctx, tenant.Tenant.ID, provider.ID,
		consumerURL, "test:integration")
	if err != nil {
		t.Fatalf("SAMLLoginStart() after restart error = %v", err)
	}
	second, err := replayed.SAMLLoginComplete(ctx, tenant.Tenant.ID, returning.LoginID,
		sign(assertion(returning.RequestID, "_returning-assertion")), "test:integration")
	if err != nil {
		t.Fatalf("SAMLLoginComplete() after restart error = %v", err)
	}
	if second.PrincipalID != first.PrincipalID {
		t.Fatalf("a returning SAML user became a different principal: %q then %q",
			first.PrincipalID, second.PrincipalID)
	}
	if second.Provisioned {
		t.Fatal("a returning SAML user was provisioned a second time")
	}

	// The completed transaction stays spent across the restart.
	if _, err := replayed.SAMLLoginComplete(ctx, tenant.Tenant.ID, completedLogin.LoginID,
		sign(spent), "test:integration"); !errors.Is(err, identityapp.ErrSAMLLoginNotFound) {
		t.Fatalf("a spent SAML login was replayable after restart: %v", err)
	}

	// The in-flight login comes back usable, because nothing about it was
	// confidential. Refusing it would be an outage with no security benefit.
	resumed, err := replayed.SAMLLoginComplete(ctx, tenant.Tenant.ID, inFlight.LoginID,
		sign(assertion(inFlight.RequestID, "_resumed-assertion")), "test:integration")
	if err != nil {
		t.Fatalf("an in-flight SAML login did not survive a restart: %v", err)
	}
	if resumed.PrincipalID != first.PrincipalID {
		t.Fatalf("the resumed login resolved to %q, want %q",
			resumed.PrincipalID, first.PrincipalID)
	}

	// Disablement is durable: it must survive a restart of its own.
	if err := replayed.SAMLProviderDisable(ctx, tenant.Tenant.ID, provider.ID,
		"contract ended", "test:integration"); err != nil {
		t.Fatalf("SAMLProviderDisable() error = %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	final, afterDisable := open()
	t.Cleanup(func() { _ = final.Close() })
	if _, err := afterDisable.SAMLLoginStart(ctx, tenant.Tenant.ID, provider.ID,
		consumerURL, "test:integration"); !errors.Is(err, identityapp.ErrSAMLProviderNotFound) {
		t.Fatalf("a disabled provider came back after a restart: %v", err)
	}
}
