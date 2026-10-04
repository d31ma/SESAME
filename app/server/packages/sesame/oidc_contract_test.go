package sesame

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// startAgainstFakeFYLO boots a real SESAME binary over the fake FYLO runtime,
// with no deployment directory — which is exactly the configuration in which
// key-backed operations must fail closed.
func startAgainstFakeFYLO(t *testing.T) *Client {
	t.Helper()

	workspace := t.TempDir()
	fakeFYLO := filepath.Join(workspace, "fake-fylo")
	if runtime.GOOS == "windows" {
		fakeFYLO += ".exe"
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate contract test file")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	build := exec.Command("go", "build", "-trimpath", "-o", fakeFYLO, "./internal/adapters/fylo/testdata/fakefylo")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake FYLO: %v\n%s", err, output)
	}
	root := filepath.Join(workspace, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	client, err := Start(context.Background(), Options{
		Binary:     testBinary,
		FYLOBinary: fakeFYLO,
		FYLORoot:   root,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestSDKOIDCClientLifecycle(t *testing.T) {
	t.Parallel()

	client := startAgainstFakeFYLO(t)
	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	tenant, err := client.TenantBootstrap(ctx, "oidc-acme")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}

	registered, err := client.ClientRegister(ctx, tenant.Tenant.ID, "billing", "confidential",
		[]string{"https://app.example/cb"}, []string{"profile"}, "first_party", nil)
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	if registered.Secret == "" || registered.Client.ID == "" {
		t.Fatalf("registration = %#v", registered)
	}
	if strings.Join(registered.Client.Scopes, " ") != "openid profile" {
		t.Fatalf("scopes = %#v; openid must always be registered", registered.Client.Scopes)
	}

	fetched, err := client.ClientGet(ctx, registered.Client.ID)
	if err != nil {
		t.Fatalf("ClientGet() error = %v", err)
	}
	if fetched.Name != "billing" || fetched.Disabled {
		t.Fatalf("client = %#v", fetched)
	}

	rotated, err := client.ClientRotateSecret(ctx, registered.Client.ID)
	if err != nil {
		t.Fatalf("ClientRotateSecret() error = %v", err)
	}
	if rotated == "" || rotated == registered.Secret {
		t.Fatal("ClientRotateSecret did not issue a new secret")
	}

	if err := client.ClientDisable(ctx, registered.Client.ID, "leaked"); err != nil {
		t.Fatalf("ClientDisable() error = %v", err)
	}
	if err := client.ClientDisable(ctx, registered.Client.ID, "leaked"); err != nil {
		t.Fatalf("repeated ClientDisable() error = %v", err)
	}
	if _, err := client.ClientRotateSecret(ctx, registered.Client.ID); !isProtocolCode(err, "client_disabled") {
		t.Fatalf("rotate after disable error = %v, want client_disabled", err)
	}

	// A wildcard redirect never reaches storage.
	if _, err := client.ClientRegister(ctx, tenant.Tenant.ID, "leaky", "public",
		[]string{"https://*.example/cb"}, nil, "first_party", nil); !isProtocolCode(err, "invalid_request") {
		t.Fatalf("wildcard redirect error = %v, want invalid_request", err)
	}
}

func TestSDKSigningKeysFailClosedWithoutADeployment(t *testing.T) {
	t.Parallel()

	client := startAgainstFakeFYLO(t)
	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	// Without a deployment key directory there is no signing key, and the
	// engine says so rather than serving an empty key set a relying party
	// would read as "this issuer signs nothing".
	keys, err := client.SigningKeys(ctx)
	if !isProtocolCode(err, "signing_not_configured") {
		t.Fatalf("SigningKeys() = %#v, %v; want signing_not_configured", keys, err)
	}
}

// TestSDKAuthorizationCodeFlow drives the whole browser flow through a real
// SESAME binary backed by a real deployment directory, so the signing key,
// the issuer, and the code lifecycle are the shipped ones.
func TestSDKAuthorizationCodeFlow(t *testing.T) {
	t.Parallel()

	const (
		verifier = "sesame-sdk-verifier-0123456789-abcdefghijklmnopq"
		password = "correct horse battery staple"
		redirect = "https://app.example/cb"
	)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	client := startAgainstDeployment(t, "https://id.example")
	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	tenant, err := client.TenantBootstrap(ctx, "flow-acme")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	identifier := PrincipalIdentifier{Namespace: "email", Value: "user@example.com"}
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := client.SetPassword(ctx, principal.ID, password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	registered, err := client.ClientRegister(ctx, tenant.Tenant.ID, "billing", "confidential",
		[]string{redirect}, nil, "first_party", nil)
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	started, err := client.Authorize(ctx, AuthorizationRequest{
		ClientID:            registered.Client.ID,
		RedirectURI:         redirect,
		ResponseType:        "code",
		Scopes:              []string{"openid"},
		State:               "csrf",
		Nonce:               "n0",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	begun, err := client.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := client.AuthenticationVerifyPassword(ctx, begun.TransactionID, password); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := client.AuthenticationComplete(ctx, begun.TransactionID, 0)
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	response, err := client.InteractionComplete(ctx, started.InteractionID, started.Secret,
		session.SessionID, session.Secret)
	if err != nil {
		t.Fatalf("InteractionComplete() error = %v", err)
	}
	if response.RedirectURI != redirect || response.State != "csrf" {
		t.Fatalf("authorization response = %#v", response)
	}

	request := TokenRequest{
		GrantType:    "authorization_code",
		Code:         response.Code,
		RedirectURI:  redirect,
		ClientID:     registered.Client.ID,
		ClientSecret: registered.Secret,
		CodeVerifier: verifier,
	}
	tokens, err := client.TokenExchange(ctx, request)
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	if tokens.TokenType != "Bearer" || tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("tokens = %#v", tokens)
	}
	if _, err := client.TokenExchange(ctx, request); !isProtocolCode(err, "invalid_grant") {
		t.Fatalf("code replay error = %v, want invalid_grant", err)
	}

	// With a deployment there is a real signing key, and the token header's
	// kid names the published one.
	keys, err := client.SigningKeys(ctx)
	if err != nil {
		t.Fatalf("SigningKeys() error = %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].Algorithm != "ES256" {
		t.Fatalf("JWKS = %#v", keys)
	}
	header, _, _ := strings.Cut(tokens.AccessToken, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("decode token header: %v", err)
	}
	var parsed struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		t.Fatalf("parse token header: %v", err)
	}
	if parsed.Algorithm != "ES256" || parsed.KeyID != keys.Keys[0].KeyID {
		t.Fatalf("token header = %#v, JWKS kid = %q", parsed, keys.Keys[0].KeyID)
	}
}

// TestSDKRefreshRotationAndReuseDetection drives a rotating family through a
// real binary, including the reuse that kills it.
func TestSDKRefreshRotationAndReuseDetection(t *testing.T) {
	t.Parallel()

	const (
		verifier = "sesame-sdk-refresh-verifier-0123456789-abcdef"
		password = "correct horse battery staple"
		redirect = "https://app.example/cb"
	)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	client := startAgainstDeployment(t, "https://id.example")
	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	tenant, err := client.TenantBootstrap(ctx, "refresh-acme")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	identifier := PrincipalIdentifier{Namespace: "email", Value: "user@example.com"}
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := client.SetPassword(ctx, principal.ID, password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	registered, err := client.ClientRegister(ctx, tenant.Tenant.ID, "offline", "confidential",
		[]string{redirect}, []string{"offline_access"}, "first_party", nil)
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	started, err := client.Authorize(ctx, AuthorizationRequest{
		ClientID:            registered.Client.ID,
		RedirectURI:         redirect,
		ResponseType:        "code",
		Scopes:              []string{"openid", "offline_access"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	begun, err := client.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := client.AuthenticationVerifyPassword(ctx, begun.TransactionID, password); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := client.AuthenticationComplete(ctx, begun.TransactionID, 0)
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	response, err := client.InteractionComplete(ctx, started.InteractionID, started.Secret,
		session.SessionID, session.Secret)
	if err != nil {
		t.Fatalf("InteractionComplete() error = %v", err)
	}

	tokens, err := client.TokenExchange(ctx, TokenRequest{
		GrantType:    "authorization_code",
		Code:         response.Code,
		RedirectURI:  redirect,
		ClientID:     registered.Client.ID,
		ClientSecret: registered.Secret,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("offline_access produced no refresh token")
	}

	refresh := func(value string) (TokenResponse, error) {
		return client.TokenExchange(ctx, TokenRequest{
			GrantType:    "refresh_token",
			RefreshToken: value,
			ClientID:     registered.Client.ID,
			ClientSecret: registered.Secret,
		})
	}

	rotated, err := refresh(tokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh error = %v", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == tokens.RefreshToken {
		t.Fatal("the refresh grant did not rotate")
	}

	// Two parties holding tokens from one family means one stole it, so
	// neither keeps the grant.
	if _, err := refresh(tokens.RefreshToken); !isProtocolCode(err, "invalid_grant") {
		t.Fatalf("reused token error = %v, want invalid_grant", err)
	}
	if _, err := refresh(rotated.RefreshToken); !isProtocolCode(err, "invalid_grant") {
		t.Fatalf("successor after reuse error = %v, want invalid_grant", err)
	}
}

// TestSDKDiscoveryIntrospectionAndRevocation drives the standards surfaces
// through a real binary against a real deployment.
func TestSDKDiscoveryIntrospectionAndRevocation(t *testing.T) {
	t.Parallel()

	const (
		verifier = "sesame-sdk-standards-verifier-0123456789-abcd"
		password = "correct horse battery staple"
		redirect = "https://app.example/cb"
		issuer   = "https://id.example"
	)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	client := startAgainstDeployment(t, issuer)
	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	metadata, err := client.Discovery(ctx, DiscoveryEndpoints{})
	if err != nil {
		t.Fatalf("Discovery() error = %v", err)
	}
	if metadata.Issuer != issuer || metadata.TokenEndpoint != issuer+"/token" {
		t.Fatalf("metadata = %#v", metadata)
	}
	// The document must not advertise a flow the engine refuses.
	for _, unsupported := range []string{"token", "id_token"} {
		for _, advertised := range metadata.ResponseTypesSupported {
			if advertised == unsupported {
				t.Fatalf("discovery advertises unsupported response_type %q", unsupported)
			}
		}
	}
	if _, err := client.Discovery(ctx, DiscoveryEndpoints{
		TokenEndpoint: "https://evil.example/token",
	}); !isProtocolCode(err, "invalid_request") {
		t.Fatalf("off-origin endpoint error = %v, want invalid_request", err)
	}

	tenant, err := client.TenantBootstrap(ctx, "standards-acme")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	identifier := PrincipalIdentifier{Namespace: "email", Value: "user@example.com"}
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := client.SetPassword(ctx, principal.ID, password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	registered, err := client.ClientRegister(ctx, tenant.Tenant.ID, "billing", "confidential",
		[]string{redirect}, []string{"offline_access"}, "first_party", nil)
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	started, err := client.Authorize(ctx, AuthorizationRequest{
		ClientID:            registered.Client.ID,
		RedirectURI:         redirect,
		ResponseType:        "code",
		Scopes:              []string{"openid", "offline_access"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	begun, err := client.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := client.AuthenticationVerifyPassword(ctx, begun.TransactionID, password); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := client.AuthenticationComplete(ctx, begun.TransactionID, 0)
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	authorized, err := client.InteractionComplete(ctx, started.InteractionID, started.Secret,
		session.SessionID, session.Secret)
	if err != nil {
		t.Fatalf("InteractionComplete() error = %v", err)
	}
	tokens, err := client.TokenExchange(ctx, TokenRequest{
		GrantType:    "authorization_code",
		Code:         authorized.Code,
		RedirectURI:  redirect,
		ClientID:     registered.Client.ID,
		ClientSecret: registered.Secret,
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}

	active, err := client.Introspect(ctx, registered.Client.ID, registered.Secret, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if !active.Active || active.Subject != principal.ID {
		t.Fatalf("introspection = %#v", active)
	}

	// Revoking the refresh family kills the refresh token. The access token
	// keeps verifying — SESAME cannot recall a signed JWT — which is exactly
	// why a resource server introspects instead of only verifying.
	if err := client.Revoke(ctx, registered.Client.ID, registered.Secret, tokens.RefreshToken); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	revoked, err := client.Introspect(ctx, registered.Client.ID, registered.Secret, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if revoked.Active {
		t.Fatal("a revoked refresh token introspects as active")
	}

	// Revoking something unknown is acknowledged identically, so the
	// endpoint cannot be used to test guesses.
	if err := client.Revoke(ctx, registered.Client.ID, registered.Secret, "nonsense"); err != nil {
		t.Fatalf("Revoke of an unknown token error = %v", err)
	}
}

// TestSDKConsentGate drives the third-party consent gate through a real
// binary: registration is not agreement, and the engine says so with a code
// the host can act on.
func TestSDKConsentGate(t *testing.T) {
	t.Parallel()

	const (
		verifier = "sesame-sdk-consent-verifier-0123456789-abcde"
		password = "correct horse battery staple"
		redirect = "https://app.example/cb"
	)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	client := startAgainstDeployment(t, "https://id.example")
	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()

	tenant, err := client.TenantBootstrap(ctx, "consent-acme")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	identifier := PrincipalIdentifier{Namespace: "email", Value: "user@example.com"}
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := client.SetPassword(ctx, principal.ID, password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	// An omitted audience takes the stricter rule.
	registered, err := client.ClientRegister(ctx, tenant.Tenant.ID, "third-party", "confidential",
		[]string{redirect}, []string{"profile"}, "", nil)
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	if registered.Client.Audience != "third_party" {
		t.Fatalf("an omitted audience defaulted to %q", registered.Client.Audience)
	}

	started, err := client.Authorize(ctx, AuthorizationRequest{
		ClientID:            registered.Client.ID,
		RedirectURI:         redirect,
		ResponseType:        "code",
		Scopes:              []string{"openid", "profile"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	begun, err := client.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := client.AuthenticationVerifyPassword(ctx, begun.TransactionID, password); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := client.AuthenticationComplete(ctx, begun.TransactionID, 0)
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	// Authentication alone is not agreement.
	if _, err := client.InteractionComplete(ctx, started.InteractionID, started.Secret,
		session.SessionID, session.Secret); !isProtocolCode(err, "consent_required") {
		t.Fatalf("third-party completion error = %v, want consent_required", err)
	}

	// A host renders a consent screen from the interaction's own scopes.
	interaction, err := client.InteractionGet(ctx, started.InteractionID)
	if err != nil {
		t.Fatalf("InteractionGet() error = %v", err)
	}
	if strings.Join(interaction.Scopes, " ") != "openid profile" {
		t.Fatalf("interaction scopes = %#v", interaction.Scopes)
	}
	if _, err := client.ConsentGrant(ctx, session.SessionID, session.Secret,
		registered.Client.ID, interaction.Scopes); err != nil {
		t.Fatalf("ConsentGrant() error = %v", err)
	}

	// The same interaction now completes.
	if _, err := client.InteractionComplete(ctx, started.InteractionID, started.Secret,
		session.SessionID, session.Secret); err != nil {
		t.Fatalf("InteractionComplete() after consent error = %v", err)
	}

	if err := client.ConsentWithdraw(ctx, principal.ID, registered.Client.ID); err != nil {
		t.Fatalf("ConsentWithdraw() error = %v", err)
	}
	withdrawn, err := client.ConsentGet(ctx, principal.ID, registered.Client.ID)
	if err != nil {
		t.Fatalf("ConsentGet() error = %v", err)
	}
	if !withdrawn.Withdrawn {
		t.Fatalf("consent = %#v after withdrawal", withdrawn)
	}
}

// startAgainstDeployment boots a real SESAME binary over a real deployment
// directory, so deployment-key-backed behaviour is exercised as shipped.
func startAgainstDeployment(t *testing.T, issuer string) *Client {
	t.Helper()

	workspace := t.TempDir()
	fakeFYLO := filepath.Join(workspace, "fake-fylo")
	if runtime.GOOS == "windows" {
		fakeFYLO += ".exe"
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate contract test file")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	build := exec.Command("go", "build", "-trimpath", "-o", fakeFYLO, "./internal/adapters/fylo/testdata/fakefylo")
	build.Dir = repositoryRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake FYLO: %v\n%s", err, output)
	}

	deploymentDir := filepath.Join(workspace, "deploy")
	initialize := exec.Command(testBinary, "init",
		"--deployment", deploymentDir, "--fylo-binary", fakeFYLO, "--issuer", issuer)
	if output, err := initialize.CombinedOutput(); err != nil {
		t.Fatalf("sesame init: %v\n%s", err, output)
	}

	client, err := Start(context.Background(), Options{
		Binary:     testBinary,
		Deployment: deploymentDir,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func isProtocolCode(err error, code string) bool {
	var protocolError *ProtocolError
	return errors.As(err, &protocolError) && protocolError.Code == code
}
