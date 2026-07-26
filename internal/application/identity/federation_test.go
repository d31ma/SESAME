package identity

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
	"strings"
	"testing"
	"time"

	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	federationdomain "github.com/d31ma/sesame/internal/domain/federation"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

const (
	fedIssuer      = "https://idp.example.com"
	fedClientID    = "sesame-at-idp"
	fedRedirectURI = "https://app.example.com/federation/callback"
	fedSecret      = "provider-client-secret"
)

// fedFixture is a tenant with one registered and configured provider, plus a
// stand-in provider that can mint ID tokens.
type fedFixture struct {
	service    *Service
	tenantID   string
	providerID string
	key        *rsa.PrivateKey
	now        time.Time
}

func newFedFixture(t *testing.T, linking string) *fedFixture {
	t.Helper()

	service, _, tenantID := bootstrapService(t)
	key := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate secrets key: %v", err)
	}
	service.UseSecretsKey(key)

	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}
	fixture := &fedFixture{
		service:  service,
		tenantID: tenantID,
		key:      signing,
		now:      time.Unix(1_700_000_000, 0).UTC(),
	}
	service.UseClock(func() time.Time { return fixture.now })

	ctx := context.Background()
	provider, instruction, err := service.ProviderRegister(ctx, tenantID, "Corp SSO",
		fedIssuer, fedClientID, fedSecret, []string{"profile", "email"},
		"sub", "email", linking, "test")
	if err != nil {
		t.Fatalf("ProviderRegister() error = %v", err)
	}
	// The engine names the URL; the host never chooses one.
	if instruction.URL != fedIssuer+federationdomain.DiscoveryPath {
		t.Fatalf("discovery URL = %q", instruction.URL)
	}
	fixture.providerID = provider.ID

	if _, err := service.ProviderConfigure(ctx, tenantID, provider.ID,
		fixture.discovery(t), fixture.jwks(t), "test"); err != nil {
		t.Fatalf("ProviderConfigure() error = %v", err)
	}
	return fixture
}

func (f *fedFixture) discovery(t *testing.T) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]any{
		"issuer":                                fedIssuer,
		"authorization_endpoint":                fedIssuer + "/authorize",
		"token_endpoint":                        fedIssuer + "/token",
		"jwks_uri":                              fedIssuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}
	return raw
}

func (f *fedFixture) jwks(t *testing.T) []byte {
	t.Helper()

	raw, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "idp-1",
		"n":   base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return raw
}

// idToken mints an assertion, with overrides so one test can forge one thing.
func (f *fedFixture) idToken(t *testing.T, nonce string, overrides map[string]any) string {
	t.Helper()

	body := map[string]any{
		"iss":            fedIssuer,
		"sub":            "provider-subject-1",
		"aud":            fedClientID,
		"nonce":          nonce,
		"iat":            f.now.Unix(),
		"exp":            f.now.Add(5 * time.Minute).Unix(),
		"email":          "person@example.com",
		"email_verified": true,
	}
	for name, value := range overrides {
		if value == nil {
			delete(body, name)
			continue
		}
		body[name] = value
	}
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "idp-1"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claims, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// start opens a login and returns its ID with the state and nonce the engine
// generated, read back out of the sealed blob the way the engine does.
func (f *fedFixture) start(t *testing.T) (string, loginSecrets) {
	t.Helper()

	login, err := f.service.LoginStart(context.Background(),
		f.tenantID, f.providerID, fedRedirectURI, "test")
	if err != nil {
		t.Fatalf("LoginStart() error = %v", err)
	}
	secrets, err := f.service.openLoginSecretsLocked(login.LoginID)
	if err != nil {
		t.Fatalf("openLoginSecretsLocked() error = %v", err)
	}
	return login.LoginID, secrets
}

// TestFederatedLoginIssuesASession is the happy path, end to end.
func TestFederatedLoginIssuesASession(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	loginID, secrets := fixture.start(t)
	result, err := fixture.service.LoginComplete(ctx, fixture.tenantID, loginID,
		fixture.idToken(t, secrets.nonce, nil), "test")
	if err != nil {
		t.Fatalf("LoginComplete() error = %v", err)
	}
	if !result.Provisioned {
		t.Fatal("a first-time federated user was not provisioned")
	}
	// The session must be usable, and must say how it was obtained.
	session, err := fixture.service.SessionVerify(result.Session.SessionID, result.Session.Secret)
	if err != nil {
		t.Fatalf("SessionVerify() error = %v", err)
	}
	if session.Assurance != authndomain.AssuranceFederated {
		t.Fatalf("assurance = %q, want %q", session.Assurance, authndomain.AssuranceFederated)
	}
}

// TestFederatedAssuranceIsNotMFA is the point of a distinct assurance level: a
// provider's assertion must not silently satisfy a step-up requirement.
func TestFederatedAssuranceIsNotMFA(t *testing.T) {
	t.Parallel()

	if authndomain.AssuranceFederated == authndomain.AssuranceMFA ||
		authndomain.AssuranceFederated == authndomain.AssurancePassword {
		t.Fatal("federated assurance is indistinguishable from a locally proven factor")
	}
}

// TestFederatedLoginIsSingleUse: a provider's assertion must not mint a second
// session by being replayed against a spent transaction.
func TestFederatedLoginIsSingleUse(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	loginID, secrets := fixture.start(t)
	token := fixture.idToken(t, secrets.nonce, nil)
	if _, err := fixture.service.LoginComplete(ctx, fixture.tenantID, loginID, token, "test"); err != nil {
		t.Fatalf("LoginComplete() error = %v", err)
	}
	_, err := fixture.service.LoginComplete(ctx, fixture.tenantID, loginID, token, "test")
	if !errors.Is(err, federationdomain.ErrLoginNotPending) {
		t.Fatalf("error = %v, want ErrLoginNotPending", err)
	}
}

// TestFederatedLoginExpires bounds an abandoned transaction.
func TestFederatedLoginExpires(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	loginID, secrets := fixture.start(t)
	token := fixture.idToken(t, secrets.nonce, nil)
	fixture.now = fixture.now.Add(federationdomain.LoginLifetime + time.Second)

	_, err := fixture.service.LoginComplete(ctx, fixture.tenantID, loginID, token, "test")
	if !errors.Is(err, federationdomain.ErrLoginExpired) {
		t.Fatalf("error = %v, want ErrLoginExpired", err)
	}
}

// TestFederatedLoginRefusesAnotherLoginsToken covers nonce binding through the
// whole service, not just the verifier.
func TestFederatedLoginRefusesAnotherLoginsToken(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	_, firstSecrets := fixture.start(t)
	secondID, _ := fixture.start(t)

	// A token minted for the first login, presented against the second.
	_, err := fixture.service.LoginComplete(ctx, fixture.tenantID, secondID,
		fixture.idToken(t, firstSecrets.nonce, nil), "test")
	if !errors.Is(err, ErrAssertionRejected) {
		t.Fatalf("error = %v, want ErrAssertionRejected", err)
	}
}

// TestFederatedLoginRejectionIsOpaque: the caller learns that it failed, never
// which check failed, because that would describe the flow to an attacker.
func TestFederatedLoginRejectionIsOpaque(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	cases := map[string]map[string]any{
		"wrong issuer":   {"iss": "https://evil.example.com"},
		"wrong audience": {"aud": "another-client"},
		"expired":        {"exp": fixture.now.Add(-2 * time.Minute).Unix()},
		"no subject":     {"sub": nil},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			loginID, secrets := fixture.start(t)
			_, err := fixture.service.LoginComplete(ctx, fixture.tenantID, loginID,
				fixture.idToken(t, secrets.nonce, overrides), "test")
			if !errors.Is(err, ErrAssertionRejected) {
				t.Fatalf("error = %v, want ErrAssertionRejected", err)
			}
		})
	}
}

// TestStrictLinkingRefusesAnUnknownSubject: under strict linking, a valid
// assertion for a subject nobody has claimed must not create an account.
func TestStrictLinkingRefusesAnUnknownSubject(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingStrict)
	ctx := context.Background()

	loginID, secrets := fixture.start(t)
	_, err := fixture.service.LoginComplete(ctx, fixture.tenantID, loginID,
		fixture.idToken(t, secrets.nonce, nil), "test")
	if !errors.Is(err, ErrSubjectNotLinked) {
		t.Fatalf("error = %v, want ErrSubjectNotLinked", err)
	}
}

// TestUnverifiedEmailCannotTakeOverAnAccount is the account-takeover case. An
// unverified email is a string the user typed at the provider.
func TestUnverifiedEmailCannotTakeOverAnAccount(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	existing, err := fixture.service.PrincipalCreate(ctx, fixture.tenantID,
		principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "victim@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	loginID, secrets := fixture.start(t)
	_, err = fixture.service.LoginComplete(ctx, fixture.tenantID, loginID,
		fixture.idToken(t, secrets.nonce, map[string]any{
			"email":          "victim@example.com",
			"email_verified": false,
		}), "test")
	if !errors.Is(err, ErrSubjectNotLinked) {
		t.Fatalf("an unverified email claimed an existing account: %v", err)
	}

	// And with the flag absent entirely, not merely false.
	loginID, secrets = fixture.start(t)
	_, err = fixture.service.LoginComplete(ctx, fixture.tenantID, loginID,
		fixture.idToken(t, secrets.nonce, map[string]any{
			"email":          "victim@example.com",
			"email_verified": nil,
		}), "test")
	if !errors.Is(err, ErrSubjectNotLinked) {
		t.Fatalf("a missing email_verified claimed an existing account: %v", err)
	}
	if fixture.service.principals[existing.ID].Status != principaldomain.StatusActive {
		t.Fatal("the victim principal was disturbed")
	}
}

// TestVerifiedEmailLinksToAnExistingPrincipal covers the matching path.
func TestVerifiedEmailLinksToAnExistingPrincipal(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	existing, err := fixture.service.PrincipalCreate(ctx, fixture.tenantID,
		principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "person@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	loginID, secrets := fixture.start(t)
	result, err := fixture.service.LoginComplete(ctx, fixture.tenantID, loginID,
		fixture.idToken(t, secrets.nonce, nil), "test")
	if err != nil {
		t.Fatalf("LoginComplete() error = %v", err)
	}
	if result.PrincipalID != existing.ID {
		t.Fatalf("principal = %q, want the existing %q", result.PrincipalID, existing.ID)
	}
	if result.Provisioned {
		t.Fatal("an existing principal was reported as provisioned")
	}
}

// TestSuspendedPrincipalCannotLogInFederated: suspension must bite here too,
// or federation becomes a way around it.
func TestSuspendedPrincipalCannotLogInFederated(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	loginID, secrets := fixture.start(t)
	first, err := fixture.service.LoginComplete(ctx, fixture.tenantID, loginID,
		fixture.idToken(t, secrets.nonce, nil), "test")
	if err != nil {
		t.Fatalf("LoginComplete() error = %v", err)
	}
	if _, err := fixture.service.PrincipalSuspend(ctx, first.PrincipalID, "test"); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}

	loginID, secrets = fixture.start(t)
	_, err = fixture.service.LoginComplete(ctx, fixture.tenantID, loginID,
		fixture.idToken(t, secrets.nonce, nil), "test")
	if !errors.Is(err, ErrSubjectNotLinked) {
		t.Fatalf("a suspended principal logged in through federation: %v", err)
	}
}

// TestCrossTenantProviderIsInvisible: one tenant must not reach another's
// provider, and must not learn that it exists.
func TestCrossTenantProviderIsInvisible(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	other, err := fixture.service.Bootstrap(ctx, "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	_, err = fixture.service.LoginStart(ctx, other.Tenant.ID, fixture.providerID,
		fedRedirectURI, "test")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("error = %v, want ErrProviderNotFound", err)
	}
}

// TestAuthorizationURLCarriesPKCEAndBinding checks what actually leaves for
// the provider.
func TestAuthorizationURLCarriesPKCEAndBinding(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)

	login, err := fixture.service.LoginStart(context.Background(),
		fixture.tenantID, fixture.providerID, fedRedirectURI, "test")
	if err != nil {
		t.Fatalf("LoginStart() error = %v", err)
	}
	parsed, err := url.Parse(login.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if parsed.Host != "idp.example.com" || parsed.Path != "/authorize" {
		t.Fatalf("authorization URL points at %q", login.AuthorizationURL)
	}
	query := parsed.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatal("the authorization request carries no S256 challenge")
	}
	if query.Get("state") == "" || query.Get("nonce") == "" {
		t.Fatal("the authorization request carries no state or nonce")
	}
	// The verifier must never leave; only its challenge may.
	secrets, err := fixture.service.openLoginSecretsLocked(login.LoginID)
	if err != nil {
		t.Fatalf("openLoginSecretsLocked() error = %v", err)
	}
	if strings.Contains(login.AuthorizationURL, secrets.verifier) {
		t.Fatal("the PKCE verifier leaked into the authorization URL")
	}
	if query.Get("code_challenge") != federationdomain.Challenge(secrets.verifier) {
		t.Fatal("the challenge does not derive from the stored verifier")
	}
}

// TestExchangeRequiresMatchingState covers the CSRF check on the callback.
func TestExchangeRequiresMatchingState(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	loginID, secrets := fixture.start(t)
	if _, err := fixture.service.LoginExchange(ctx, fixture.tenantID, loginID,
		"a-forged-state", "provider-code"); !errors.Is(err, ErrAssertionRejected) {
		t.Fatalf("error = %v, want ErrAssertionRejected", err)
	}

	instruction, err := fixture.service.LoginExchange(ctx, fixture.tenantID, loginID,
		secrets.state, "provider-code")
	if err != nil {
		t.Fatalf("LoginExchange() error = %v", err)
	}
	if instruction.URL != fedIssuer+"/token" || instruction.Method != "POST" {
		t.Fatalf("token instruction = %#v", instruction)
	}
	if instruction.Form["code_verifier"] != secrets.verifier {
		t.Fatal("the exchange does not carry the PKCE verifier")
	}
	if instruction.Form["client_secret"] != fedSecret {
		t.Fatal("the exchange does not carry the provider's client secret")
	}
}

// TestProviderConfigureRefusesAHostileDocument proves the untrusted-input
// boundary is enforced at the service, not only in the domain.
func TestProviderConfigureRefusesAHostileDocument(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	hostile, err := json.Marshal(map[string]any{
		"issuer":                 fedIssuer,
		"authorization_endpoint": fedIssuer + "/authorize",
		"token_endpoint":         "https://evil.example.com/token",
		"jwks_uri":               fedIssuer + "/jwks",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := fixture.service.ProviderConfigure(ctx, fixture.tenantID, fixture.providerID,
		hostile, fixture.jwks(t), "test"); err == nil {
		t.Fatal("ProviderConfigure accepted an off-origin token endpoint")
	}
}

// TestUnconfiguredProviderCannotStartALogin fails closed: without validated
// metadata SESAME does not know where to send anyone.
func TestUnconfiguredProviderCannotStartALogin(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	key := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate secrets key: %v", err)
	}
	service.UseSecretsKey(key)

	ctx := context.Background()
	provider, _, err := service.ProviderRegister(ctx, tenantID, "Corp SSO", fedIssuer,
		fedClientID, fedSecret, nil, "sub", "email",
		federationdomain.LinkingVerifiedEmail, "test")
	if err != nil {
		t.Fatalf("ProviderRegister() error = %v", err)
	}
	_, err = service.LoginStart(ctx, tenantID, provider.ID, fedRedirectURI, "test")
	if !errors.Is(err, ErrProviderNotConfigured) {
		t.Fatalf("error = %v, want ErrProviderNotConfigured", err)
	}
}

// TestFederationSurvivesSnapshotRestore is the projection regression: a
// snapshot-seeded restart must not forget providers or links.
func TestFederationSurvivesSnapshotRestore(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	loginID, secrets := fixture.start(t)
	result, err := fixture.service.LoginComplete(ctx, fixture.tenantID, loginID,
		fixture.idToken(t, secrets.nonce, nil), "test")
	if err != nil {
		t.Fatalf("LoginComplete() error = %v", err)
	}

	fixture.service.mu.Lock()
	state := fixture.service.exportStateLocked()
	fixture.service.mu.Unlock()

	if len(state.Providers) != 1 {
		t.Fatalf("the snapshot carries %d providers, want 1", len(state.Providers))
	}
	if len(state.FederatedLinks) != 1 {
		t.Fatalf("the snapshot carries %d links, want 1", len(state.FederatedLinks))
	}
	// The provider's client secret must travel sealed, never in the clear.
	if strings.Contains(state.Providers[0].SecretSealed, fedSecret) {
		t.Fatal("the provider's client secret is in the snapshot in the clear")
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	if strings.Contains(string(encoded), fedSecret) {
		t.Fatal("the provider's client secret appears in the serialised snapshot")
	}
	if strings.Contains(string(encoded), result.Session.Secret) {
		t.Fatal("a session secret appears in the serialised snapshot")
	}
}

// TestProviderDisableStopsNewLogins covers the operator's remedy for a
// compromised provider: stop trusting new assertions from it.
func TestProviderDisableStopsNewLogins(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	// A login already in flight when the provider is disabled must not
	// complete: the provider that vouches for it is no longer trusted.
	inFlight, _ := fixture.start(t)

	if err := fixture.service.ProviderDisable(ctx, fixture.tenantID, fixture.providerID,
		"compromised", "test"); err != nil {
		t.Fatalf("ProviderDisable() error = %v", err)
	}
	// Idempotent: a second disable appends nothing and still succeeds.
	if err := fixture.service.ProviderDisable(ctx, fixture.tenantID, fixture.providerID,
		"compromised", "test"); err != nil {
		t.Fatalf("a second ProviderDisable() error = %v", err)
	}

	if _, err := fixture.service.LoginStart(ctx, fixture.tenantID, fixture.providerID,
		fedRedirectURI, "test"); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("LoginStart() after disable error = %v, want ErrProviderNotFound", err)
	}
	if _, err := fixture.service.ProviderGet(fixture.tenantID, fixture.providerID); !errors.Is(
		err, ErrProviderNotFound) {
		t.Fatalf("ProviderGet() after disable error = %v, want ErrProviderNotFound", err)
	}
	_, err := fixture.service.LoginComplete(ctx, fixture.tenantID, inFlight,
		fixture.idToken(t, "anything", nil), "test")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("an in-flight login completed through a disabled provider: %v", err)
	}
}

// TestProviderDisableIsTenantScoped: one tenant must not disable another's
// provider.
func TestProviderDisableIsTenantScoped(t *testing.T) {
	t.Parallel()

	fixture := newFedFixture(t, federationdomain.LinkingVerifiedEmail)
	ctx := context.Background()

	other, err := fixture.service.Bootstrap(ctx, "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if err := fixture.service.ProviderDisable(ctx, other.Tenant.ID, fixture.providerID,
		"", "test"); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("error = %v, want ErrProviderNotFound", err)
	}
	// The provider is untouched.
	if _, err := fixture.service.ProviderGet(fixture.tenantID, fixture.providerID); err != nil {
		t.Fatalf("the provider was disabled across a tenant boundary: %v", err)
	}
}
