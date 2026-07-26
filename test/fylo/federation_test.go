package fylo_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	federationdomain "github.com/d31ma/sesame/internal/domain/federation"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// TestRealFYLOFederationSurvivesRestart proves against a real FYLO runtime
// that federation state is durable: a registered provider, an in-flight
// login, and an external subject link all replay into the same projection
// state after a process restart.
//
// The in-memory fake cannot prove this. Three things are at stake and each
// fails differently if the projection is wrong. A provider that does not
// replay means every federated login refuses after a restart. A subject link
// that does not replay means a returning user is treated as a stranger and,
// under verified-email linking, gets a *second* principal. And an in-flight
// login must come back unusable rather than absent: its sealed nonce is
// deliberately not snapshotted, so completing it after a restart has to fail
// closed rather than proceed without the value that binds the assertion to
// this attempt.
func TestRealFYLOFederationSurvivesRestart(t *testing.T) {
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
	root, err := os.MkdirTemp("", "sesame-federation-*")
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
		issuer      = "https://idp.example.com"
		idpClientID = "sesame-at-idp"
		callback    = "https://app.example/federation/cb"
		idpSecret   = "provider-client-secret"
	)
	now := time.Unix(1_700_000_000, 0).UTC()

	// One secrets key across both processes, as a deployment key directory
	// would supply. Without it the second process could not open the sealed
	// provider secret, and the test would prove nothing about replay.
	secretsKey := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	if _, err := rand.Read(secretsKey); err != nil {
		t.Fatalf("generate secrets key: %v", err)
	}
	providerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
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
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	discovery := federationDocument(t, issuer)
	keySet := federationKeySet(t, providerKey)

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	provider, instruction, err := service.ProviderRegister(ctx, tenant.Tenant.ID,
		"Corp SSO", issuer, idpClientID, idpSecret, []string{"email"},
		"sub", "email", federationdomain.LinkingVerifiedEmail, "test:integration")
	if err != nil {
		t.Fatalf("ProviderRegister() error = %v", err)
	}
	if instruction.URL != issuer+federationdomain.DiscoveryPath {
		t.Fatalf("discovery URL = %q", instruction.URL)
	}
	if _, err := service.ProviderConfigure(ctx, tenant.Tenant.ID, provider.ID,
		discovery, keySet, "test:integration"); err != nil {
		t.Fatalf("ProviderConfigure() error = %v", err)
	}

	// One login is completed, which creates the subject link; a second is
	// left in flight, so the restart has both states to replay.
	completedLogin, err := service.LoginStart(ctx, tenant.Tenant.ID, provider.ID,
		callback, "test:integration")
	if err != nil {
		t.Fatalf("LoginStart() error = %v", err)
	}
	assertion := federationAssertion(t, providerKey, issuer, idpClientID,
		nonceFromAuthorizationURL(t, completedLogin.AuthorizationURL), now)
	first, err := service.LoginComplete(ctx, tenant.Tenant.ID, completedLogin.LoginID,
		assertion, "test:integration")
	if err != nil {
		t.Fatalf("LoginComplete() error = %v", err)
	}
	if !first.Provisioned {
		t.Fatal("a first-time federated user was not provisioned")
	}
	inFlight, err := service.LoginStart(ctx, tenant.Tenant.ID, provider.ID,
		callback, "test:integration")
	if err != nil {
		t.Fatalf("LoginStart() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// ---- restart ----
	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	// The provider replays, including its sealed secret: an exchange built
	// after the restart must still carry the credential.
	view, err := replayed.ProviderGet(tenant.Tenant.ID, provider.ID)
	if err != nil {
		t.Fatalf("ProviderGet() after restart error = %v", err)
	}
	if view.Provider.Issuer != issuer {
		t.Fatalf("issuer after restart = %q", view.Provider.Issuer)
	}
	// Metadata is deliberately not snapshotted — it is refetchable, and a
	// stale copy could pin SESAME to a rotated key — so the provider comes
	// back unconfigured and must be reconfigured before use.
	if view.Configured {
		t.Fatal("validated metadata survived the restart; it must be refetched")
	}
	if _, err := replayed.LoginStart(ctx, tenant.Tenant.ID, provider.ID,
		callback, "test:integration"); !errors.Is(err, identityapp.ErrProviderNotConfigured) {
		t.Fatalf("LoginStart() after restart error = %v, want ErrProviderNotConfigured", err)
	}
	if _, err := replayed.ProviderConfigure(ctx, tenant.Tenant.ID, provider.ID,
		discovery, keySet, "test:integration"); err != nil {
		t.Fatalf("ProviderConfigure() after restart error = %v", err)
	}

	// The subject link replays: the same external user is the same principal,
	// and is not provisioned a second time.
	returning, err := replayed.LoginStart(ctx, tenant.Tenant.ID, provider.ID,
		callback, "test:integration")
	if err != nil {
		t.Fatalf("LoginStart() after restart error = %v", err)
	}
	second, err := replayed.LoginComplete(ctx, tenant.Tenant.ID, returning.LoginID,
		federationAssertion(t, providerKey, issuer, idpClientID,
			nonceFromAuthorizationURL(t, returning.AuthorizationURL), now),
		"test:integration")
	if err != nil {
		t.Fatalf("LoginComplete() after restart error = %v", err)
	}
	if second.PrincipalID != first.PrincipalID {
		t.Fatalf("a returning federated user became a different principal: %q then %q",
			first.PrincipalID, second.PrincipalID)
	}
	if second.Provisioned {
		t.Fatal("a returning federated user was provisioned a second time")
	}

	// The completed login stays spent across the restart.
	if _, err := replayed.LoginComplete(ctx, tenant.Tenant.ID, completedLogin.LoginID,
		assertion, "test:integration"); !errors.Is(err, federationdomain.ErrLoginNotPending) {
		t.Fatalf("a spent federated login was replayable after restart: %v", err)
	}

	// The in-flight login fails closed: its sealed nonce did not travel, so
	// there is nothing to bind an assertion to and it must not proceed.
	_, err = replayed.LoginComplete(ctx, tenant.Tenant.ID, inFlight.LoginID,
		assertion, "test:integration")
	if err == nil {
		t.Fatal("an in-flight login completed after a restart without its nonce")
	}

	// The just-in-time provisioned principal is a real one: it claimed the
	// email identifier, so a later attempt to claim the same address must
	// conflict rather than silently create a duplicate.
	_, err = replayed.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "federated@example.com"},
		"test:integration")
	if !errors.Is(err, identityapp.ErrIdentifierConflict) {
		t.Fatalf("the provisioned principal's identifier did not survive the restart: %v", err)
	}
}

func federationDocument(t *testing.T, issuer string) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}
	return raw
}

func federationKeySet(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "idp-1",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatalf("marshal key set: %v", err)
	}
	return raw
}

// nonceFromAuthorizationURL reads the nonce the engine generated out of the
// URL it built, which is the only place a caller legitimately sees it.
func nonceFromAuthorizationURL(t *testing.T, authorizationURL string) string {
	t.Helper()

	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	nonce := parsed.Query().Get("nonce")
	if nonce == "" {
		t.Fatal("the authorization URL carries no nonce")
	}
	return nonce
}

func federationAssertion(
	t *testing.T,
	key *rsa.PrivateKey,
	issuer, audience, nonce string,
	now time.Time,
) string {
	t.Helper()

	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "idp-1"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss":            issuer,
		"sub":            "provider-subject-1",
		"aud":            audience,
		"nonce":          nonce,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"email":          "federated@example.com",
		"email_verified": true,
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}
