package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

func TestDiscoveryUsesHostRoutesUnderTheIssuer(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)

	metadata, err := fixture.service.Discovery(oidcdomain.Endpoints{})
	if err != nil {
		t.Fatalf("Discovery() error = %v", err)
	}
	if metadata.Issuer != flowIssuer || metadata.TokenEndpoint != flowIssuer+"/token" {
		t.Fatalf("metadata = %#v", metadata)
	}

	// A host that mounts its routes elsewhere says so.
	custom, err := fixture.service.Discovery(oidcdomain.Endpoints{
		Authorization: "/oauth/authorize",
		Token:         "/oauth/token",
	})
	if err != nil {
		t.Fatalf("Discovery() error = %v", err)
	}
	if custom.AuthorizationEndpoint != flowIssuer+"/oauth/authorize" ||
		custom.TokenEndpoint != flowIssuer+"/oauth/token" ||
		custom.JWKSURI != flowIssuer+"/.well-known/jwks.json" {
		t.Fatalf("metadata = %#v", custom)
	}

	// But not somewhere else entirely.
	if _, err := fixture.service.Discovery(oidcdomain.Endpoints{
		Token: "https://evil.example/token",
	}); err == nil {
		t.Fatal("Discovery published an off-origin token endpoint")
	}

	// Without a configured issuer there is no document to publish.
	fixture.service.UseIssuer("")
	if _, err := fixture.service.Discovery(oidcdomain.Endpoints{}); !errors.Is(err, ErrNoIssuer) {
		t.Fatalf("Discovery without an issuer error = %v", err)
	}
}

// TestIntrospectionReflectsLiveState is the reason introspection exists: an
// access token is a signed JWT SESAME cannot recall, so a verifying signature
// is not the same as a standing grant.
func TestIntrospectionReflectsLiveState(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()
	request := TokenRequest{ClientID: fixture.clientID, ClientSecret: fixture.secret}

	access, err := fixture.service.Introspect(request, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if !access.Active || access.Subject != fixture.principalID ||
		access.TokenType != "Bearer" || access.SessionID != fixture.sessionID {
		t.Fatalf("access introspection = %#v", access)
	}

	refresh, err := fixture.service.Introspect(request, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if !refresh.Active || refresh.TokenType != "refresh_token" ||
		!strings.Contains(refresh.Scope, oidcdomain.ScopeOfflineAccess) {
		t.Fatalf("refresh introspection = %#v", refresh)
	}

	// Revoking the session makes both dead, even though the access token's
	// signature and expiry are untouched.
	if err := fixture.service.SessionRevoke(ctx, fixture.sessionID, "signed out", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	for name, token := range map[string]string{
		"access":  tokens.AccessToken,
		"refresh": tokens.RefreshToken,
	} {
		result, err := fixture.service.Introspect(request, token)
		if err != nil {
			t.Fatalf("Introspect() error = %v", err)
		}
		if result.Active {
			t.Fatalf("the %s token is still active after session revocation", name)
		}
		// An inactive answer carries nothing else at all.
		if result != (Introspection{Active: false}) {
			t.Fatalf("inactive introspection leaked fields: %#v", result)
		}
	}
}

func TestIntrospectionRefusesOtherClientsTokens(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()

	other, err := fixture.service.ClientRegister(ctx, fixture.tenantID, "other",
		oidcdomain.TypeConfidential, []string{flowRedirectURI}, nil, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	otherRequest := TokenRequest{ClientID: other.Client.ID, ClientSecret: other.Secret}

	for name, token := range map[string]string{
		"access":  tokens.AccessToken,
		"refresh": tokens.RefreshToken,
	} {
		result, err := fixture.service.Introspect(otherRequest, token)
		if err != nil {
			t.Fatalf("Introspect() error = %v", err)
		}
		if result.Active {
			t.Fatalf("a second client introspected the first client's %s token", name)
		}
	}

	// The endpoint itself is authenticated: a wrong secret gets no answer at
	// all rather than an inactive one.
	if _, err := fixture.service.Introspect(
		TokenRequest{ClientID: fixture.clientID, ClientSecret: "hunter2"},
		tokens.AccessToken,
	); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("unauthenticated Introspect error = %v", err)
	}

	// Garbage is inactive, not an error, so the endpoint is not an oracle.
	for _, token := range []string{"", "not-a-token", "rft_00000000000000000000000000000000.x", tokens.AccessToken + "x"} {
		result, err := fixture.service.Introspect(
			TokenRequest{ClientID: fixture.clientID, ClientSecret: fixture.secret}, token)
		if err != nil || result.Active {
			t.Fatalf("Introspect(%q) = %#v, %v", token, result, err)
		}
	}
}

func TestIntrospectionExpiresWithTheToken(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	request := TokenRequest{ClientID: fixture.clientID, ClientSecret: fixture.secret}

	fixture.now = fixture.now.Add(AccessTokenLifetime + 2*time.Minute)
	result, err := fixture.service.Introspect(request, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if result.Active {
		t.Fatal("an expired access token introspected as active")
	}
	// The refresh token has its own, longer bound and is still alive.
	refresh, err := fixture.service.Introspect(request, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if !refresh.Active {
		t.Fatal("the refresh token expired with the access token")
	}
}

func TestRevokeEndsTheRefreshFamily(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()
	request := TokenRequest{ClientID: fixture.clientID, ClientSecret: fixture.secret}

	if err := fixture.service.Revoke(ctx, request, tokens.RefreshToken, "test"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if _, err := fixture.service.TokenExchange(ctx,
		fixture.refreshRequest(tokens.RefreshToken, ""), "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("refresh after revocation error = %v", err)
	}
	introspected, err := fixture.service.Introspect(request, tokens.RefreshToken)
	if err != nil || introspected.Active {
		t.Fatalf("a revoked refresh token introspects as %#v", introspected)
	}
}

// TestRevokeIsNotAnOracle pins RFC 7009 section 2.2: an unknown, malformed,
// or someone else's token gets the same silent success as a real one, so the
// endpoint cannot be used to test token guesses.
func TestRevokeIsNotAnOracle(t *testing.T) {
	t.Parallel()

	fixture, tokens := offlineFixture(t)
	ctx := context.Background()
	request := TokenRequest{ClientID: fixture.clientID, ClientSecret: fixture.secret}

	for _, token := range []string{
		"",
		"not-a-token",
		"rft_00000000000000000000000000000000.x",
		tokens.AccessToken,
	} {
		if err := fixture.service.Revoke(ctx, request, token, "test"); err != nil {
			t.Fatalf("Revoke(%q) error = %v", token, err)
		}
	}
	// None of that touched the real grant.
	if _, err := fixture.service.TokenExchange(ctx,
		fixture.refreshRequest(tokens.RefreshToken, ""), "test"); err != nil {
		t.Fatalf("the grant was disturbed by unrelated revocations: %v", err)
	}

	// A second client's revocation attempt also succeeds silently and does
	// nothing.
	other, err := fixture.service.ClientRegister(ctx, fixture.tenantID, "other",
		oidcdomain.TypeConfidential, []string{flowRedirectURI}, nil, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	if err := fixture.service.Revoke(ctx,
		TokenRequest{ClientID: other.Client.ID, ClientSecret: other.Secret},
		tokens.RefreshToken, "test"); err != nil {
		t.Fatalf("cross-client Revoke error = %v", err)
	}
	if _, err := fixture.service.Introspect(request, tokens.RefreshToken); err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}

	// The endpoint still requires the caller to authenticate.
	if err := fixture.service.Revoke(ctx,
		TokenRequest{ClientID: fixture.clientID, ClientSecret: "hunter2"},
		tokens.RefreshToken, "test"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("unauthenticated Revoke error = %v", err)
	}
}
