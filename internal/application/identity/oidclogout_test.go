package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

const postLogoutURI = "https://app.example/signed-out"

// logoutFixture registers a client that may return somewhere after logout and
// runs one authorization through to a token set with a refresh token.
func logoutFixture(t *testing.T) (*flowFixture, TokenResponse) {
	t.Helper()

	fixture := newFlowFixture(t)
	ctx := context.Background()

	registered, err := fixture.service.ClientRegister(ctx, fixture.tenantID, "logout-client",
		oidcdomain.TypeConfidential, []string{flowRedirectURI},
		[]string{"profile", oidcdomain.ScopeOfflineAccess}, oidcdomain.AudienceFirstParty,
		[]string{postLogoutURI}, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	fixture.clientID = registered.Client.ID
	fixture.secret = registered.Secret

	started, err := fixture.service.AuthorizationStart(ctx, AuthorizationRequest{
		ClientID:            fixture.clientID,
		RedirectURI:         flowRedirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{"profile", oidcdomain.ScopeOfflineAccess},
		CodeChallenge:       flowChallenge(),
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}, "test")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	response, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	tokens, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test")
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	return fixture, tokens
}

// TestLogoutEndsEverythingRestingOnTheSession is the property that makes this
// a logout rather than a gesture: revoking the session also ends every refresh
// grant that rests on it, so the client cannot quietly keep minting tokens.
func TestLogoutEndsEverythingRestingOnTheSession(t *testing.T) {
	t.Parallel()

	fixture, tokens := logoutFixture(t)
	ctx := context.Background()

	// Both are live before logout.
	if _, err := fixture.service.SessionVerify(fixture.sessionID, fixture.sessionKey); err != nil {
		t.Fatalf("SessionVerify() before logout error = %v", err)
	}
	introspection := TokenRequest{ClientID: fixture.clientID, ClientSecret: fixture.secret}
	if active, _ := fixture.service.Introspect(introspection, tokens.AccessToken); !active.Active {
		t.Fatal("the access token was not active before logout")
	}

	result, err := fixture.service.Logout(ctx, LogoutRequest{
		IDTokenHint:           tokens.IDToken,
		PostLogoutRedirectURI: postLogoutURI,
		State:                 "client-state",
	}, "test")
	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if !result.SessionRevoked || result.SessionID != fixture.sessionID ||
		result.PrincipalID != fixture.principalID || result.ClientID != fixture.clientID {
		t.Fatalf("result = %#v", result)
	}

	redirect, err := LogoutRedirect(result)
	if err != nil {
		t.Fatalf("LogoutRedirect() error = %v", err)
	}
	if redirect != postLogoutURI+"?state=client-state" {
		t.Fatalf("redirect = %q", redirect)
	}

	// The session is gone.
	if _, err := fixture.service.SessionVerify(fixture.sessionID, fixture.sessionKey); !errors.Is(
		err, ErrSessionInactive) {
		t.Fatalf("SessionVerify() after logout error = %v", err)
	}
	// So is the refresh grant that rested on it.
	if _, err := fixture.service.TokenExchange(ctx,
		fixture.refreshRequest(tokens.RefreshToken, ""), "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("a refresh survived logout: %v", err)
	}
	// And introspection reports both dead.
	if active, _ := fixture.service.Introspect(introspection, tokens.AccessToken); active.Active {
		t.Fatal("the access token is still active after logout")
	}

	// Logout is idempotent: a second click is not an error.
	again, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: tokens.IDToken}, "test")
	if err != nil {
		t.Fatalf("repeated Logout() error = %v", err)
	}
	if again.SessionRevoked {
		t.Fatal("the second logout claimed to revoke an already-ended session")
	}
}

func TestLogoutRequiresAHintItIssued(t *testing.T) {
	t.Parallel()

	fixture, tokens := logoutFixture(t)
	ctx := context.Background()

	// No hint: SESAME holds no browser session of its own, so there is
	// nothing to end.
	if _, err := fixture.service.Logout(ctx, LogoutRequest{}, "test"); !errors.Is(
		err, ErrInvalidLogoutHint) {
		t.Fatalf("Logout without a hint error = %v", err)
	}

	// A token signed by somebody else.
	stranger, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	forged, err := stranger.Sign(tokendomain.Claims{
		Issuer:    flowIssuer,
		Subject:   fixture.principalID,
		Audience:  fixture.clientID,
		ExpiresAt: fixture.now.Add(time.Hour).Unix(),
		IssuedAt:  fixture.now.Unix(),
		Extra:     map[string]any{"sid": fixture.sessionID},
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: forged}, "test"); !errors.Is(
		err, ErrInvalidLogoutHint) {
		t.Fatalf("Logout with a forged hint error = %v", err)
	}

	for name, hint := range map[string]string{
		"garbage":      "not-a-token",
		"access token": tokens.AccessToken,
	} {
		// An access token carries a sid too, but it is issued for a different
		// purpose; what matters is that neither garbage nor a token from
		// another issuer ends a session.
		if _, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: hint}, "test"); err != nil {
			if !errors.Is(err, ErrInvalidLogoutHint) {
				t.Fatalf("Logout with a %s hint error = %v", name, err)
			}
		}
	}
	// The genuine hint still works after all that.
	if _, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: tokens.IDToken}, "test"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
}

// TestLogoutAcceptsAnExpiredHint pins a deliberate tolerance: a user reaching
// for "sign out" is often doing so because their tokens have aged.
func TestLogoutAcceptsAnExpiredHint(t *testing.T) {
	t.Parallel()

	fixture, tokens := logoutFixture(t)
	ctx := context.Background()

	fixture.now = fixture.now.Add(IDTokenLifetime + time.Hour)
	// The same token no longer verifies for anything that authorizes.
	if _, _, err := fixture.signingKey.Verify(tokens.IDToken, flowIssuer, fixture.clientID, fixture.now); err == nil {
		t.Fatal("the ID token has not expired")
	}
	// But it still names the session to end.
	result, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: tokens.IDToken}, "test")
	if err != nil {
		t.Fatalf("Logout with an expired hint error = %v", err)
	}
	if !result.SessionRevoked {
		t.Fatal("an expired hint did not end its session")
	}
}

// TestLogoutRefusesAnUnregisteredReturn is the open-redirect guard: logout is
// a redirect endpoint like any other.
func TestLogoutRefusesAnUnregisteredReturn(t *testing.T) {
	t.Parallel()

	fixture, tokens := logoutFixture(t)
	ctx := context.Background()

	for _, uri := range []string{
		"https://evil.example/signed-out",
		postLogoutURI + "/extra",
		postLogoutURI + "?next=https://evil.example",
		flowRedirectURI, // registered for authorization, not for logout
	} {
		if _, err := fixture.service.Logout(ctx, LogoutRequest{
			IDTokenHint:           tokens.IDToken,
			PostLogoutRedirectURI: uri,
		}, "test"); !errors.Is(err, ErrInvalidPostLogoutRedirect) {
			t.Fatalf("Logout accepted return URI %q: %v", uri, err)
		}
	}
	// A refused redirect ends nothing, so the session is still live.
	if _, err := fixture.service.SessionVerify(fixture.sessionID, fixture.sessionKey); err != nil {
		t.Fatalf("a refused logout ended the session anyway: %v", err)
	}

	// Omitting the return entirely is fine; the host renders its own page.
	result, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: tokens.IDToken}, "test")
	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if result.RedirectURI != "" {
		t.Fatalf("redirect = %q, want none", result.RedirectURI)
	}
	redirect, err := LogoutRedirect(result)
	if err != nil || redirect != "" {
		t.Fatalf("LogoutRedirect() = %q, %v", redirect, err)
	}
}

// TestLogoutCannotEndAnotherPrincipalsSession guards the confused-deputy case:
// a hint whose subject does not own the session it names ends nothing.
func TestLogoutCannotEndAnotherPrincipalsSession(t *testing.T) {
	t.Parallel()

	fixture, _ := logoutFixture(t)
	ctx := context.Background()

	stranger, err := fixture.service.PrincipalCreate(ctx, fixture.tenantID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "stranger@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	// A validly signed hint naming my session but the stranger's subject.
	forged, err := fixture.signingKey.Sign(tokendomain.Claims{
		Issuer:    flowIssuer,
		Subject:   stranger.ID,
		Audience:  fixture.clientID,
		ExpiresAt: fixture.now.Add(time.Hour).Unix(),
		IssuedAt:  fixture.now.Unix(),
		Extra:     map[string]any{"sid": fixture.sessionID},
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: forged}, "test"); !errors.Is(
		err, ErrInvalidLogoutHint) {
		t.Fatalf("a mismatched subject ended a session: %v", err)
	}
	if _, err := fixture.service.SessionVerify(fixture.sessionID, fixture.sessionKey); err != nil {
		t.Fatalf("the session was ended anyway: %v", err)
	}
}

func TestLogoutFailsClosedWithoutKeyOrIssuer(t *testing.T) {
	t.Parallel()

	fixture, tokens := logoutFixture(t)
	ctx := context.Background()

	fixture.service.UseIssuer("")
	if _, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: tokens.IDToken}, "test"); !errors.Is(
		err, ErrNoIssuer) {
		t.Fatalf("Logout without an issuer error = %v", err)
	}
	fixture.service.UseIssuer(flowIssuer)
	fixture.service.UseSigningKey(nil)
	if _, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: tokens.IDToken}, "test"); !errors.Is(
		err, tokendomain.ErrNoSigningKey) {
		t.Fatalf("Logout without a signing key error = %v", err)
	}
}

func TestDiscoveryAdvertisesTheEndSessionEndpoint(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	metadata, err := fixture.service.Discovery(oidcdomain.Endpoints{})
	if err != nil {
		t.Fatalf("Discovery() error = %v", err)
	}
	if metadata.EndSessionEndpoint != flowIssuer+"/logout" {
		t.Fatalf("end_session_endpoint = %q", metadata.EndSessionEndpoint)
	}
	if _, err := fixture.service.Discovery(oidcdomain.Endpoints{
		EndSession: "https://evil.example/logout",
	}); err == nil {
		t.Fatal("Discovery published an off-origin end-session endpoint")
	}
}
