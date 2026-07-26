package adversarial_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/d31ma/sesame/clients/go/sesame"
)

// TestReplay covers every value SESAME hands out that must work exactly once.
func TestReplay(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	t.Run("authorization code replay", func(t *testing.T) {
		response := deploy.authorize(t, session)
		if _, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code)); err != nil {
			t.Fatalf("the first redemption failed: %v", err)
		}
		_, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code))
		refused(t, "authorization code replay", err, "invalid_grant")
	})

	t.Run("interaction handle replay", func(t *testing.T) {
		started, err := deploy.client.Authorize(ctx, authorizationRequest(deploy))
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}
		if _, err := deploy.client.InteractionComplete(ctx, started.InteractionID, started.Secret,
			session.SessionID, session.Secret); err != nil {
			t.Fatalf("the first completion failed: %v", err)
		}
		// A completed interaction issues one code, not one per attempt.
		_, err = deploy.client.InteractionComplete(ctx, started.InteractionID, started.Secret,
			session.SessionID, session.Secret)
		refused(t, "interaction handle replay", err, "interaction_closed")
	})

	t.Run("refresh token replay kills the family", func(t *testing.T) {
		response := deploy.authorize(t, session)
		tokens, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code))
		if err != nil {
			t.Fatalf("TokenExchange() error = %v", err)
		}
		rotate := func(value string) (string, error) {
			next, err := deploy.client.TokenExchange(ctx, sesameRefresh(deploy, value))
			return next.RefreshToken, err
		}
		successor, err := rotate(tokens.RefreshToken)
		if err != nil {
			t.Fatalf("the first rotation failed: %v", err)
		}
		_, err = rotate(tokens.RefreshToken)
		refused(t, "refresh token replay", err, "invalid_grant")
		// The legitimate successor dies with the family, which is the point:
		// SESAME cannot tell which holder is the thief.
		_, err = rotate(successor)
		refused(t, "use of a successor after reuse detection", err, "invalid_grant")
	})
}

// TestConfusedDeputy covers one party presenting another party's credential
// and expecting SESAME to act on it.
func TestConfusedDeputy(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	attacker, err := deploy.client.ClientRegister(ctx, deploy.tenantID, "attacker-app", "confidential",
		[]string{redirectURI}, []string{"profile", "offline_access"}, "first_party", []string{logoutURI})
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	t.Run("another client redeems the code", func(t *testing.T) {
		response := deploy.authorize(t, session)
		request := deploy.tokenRequest(response.Code)
		request.ClientID = attacker.Client.ID
		request.ClientSecret = attacker.Secret
		_, err := deploy.client.TokenExchange(ctx, request)
		refused(t, "code redemption by another client", err, "invalid_grant")
	})

	t.Run("another client introspects the token", func(t *testing.T) {
		response := deploy.authorize(t, session)
		tokens, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code))
		if err != nil {
			t.Fatalf("TokenExchange() error = %v", err)
		}
		result, err := deploy.client.Introspect(ctx, attacker.Client.ID, attacker.Secret, tokens.AccessToken)
		if err != nil {
			t.Fatalf("Introspect() error = %v", err)
		}
		if result.Active {
			t.Fatal("another client introspected a token it was not issued")
		}
	})

	t.Run("another client revokes the grant", func(t *testing.T) {
		response := deploy.authorize(t, session)
		tokens, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code))
		if err != nil {
			t.Fatalf("TokenExchange() error = %v", err)
		}
		// RFC 7009 requires success even for a token the caller cannot
		// revoke, so the attack is silent — and must change nothing.
		if err := deploy.client.Revoke(ctx, attacker.Client.ID, attacker.Secret, tokens.RefreshToken); err != nil {
			t.Fatalf("Revoke() error = %v", err)
		}
		if _, err := deploy.client.TokenExchange(ctx, sesameRefresh(deploy, tokens.RefreshToken)); err != nil {
			t.Fatalf("a cross-client revocation ended the grant: %v", err)
		}
	})

	t.Run("wrong client secret", func(t *testing.T) {
		response := deploy.authorize(t, session)
		request := deploy.tokenRequest(response.Code)
		request.ClientSecret = "hunter2"
		_, err := deploy.client.TokenExchange(ctx, request)
		refused(t, "code redemption with a wrong client secret", err, "client_not_found")
	})
}

// TestOpenRedirect covers every place SESAME hands a browser somewhere.
func TestOpenRedirect(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	t.Run("authorization redirect", func(t *testing.T) {
		for _, candidate := range []string{
			"https://evil.example/cb",
			redirectURI + "/../evil",
			redirectURI + "?next=https://evil.example",
			redirectURI + "@evil.example",
			"https://app.example.evil.test/cb",
			"//evil.example/cb",
		} {
			request := authorizationRequest(deploy)
			request.RedirectURI = candidate
			_, err := deploy.client.Authorize(ctx, request)
			if err == nil {
				t.Fatalf("the authorization endpoint accepted redirect %q", candidate)
			}
		}
	})

	t.Run("post-logout redirect", func(t *testing.T) {
		response := deploy.authorize(t, session)
		tokens, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code))
		if err != nil {
			t.Fatalf("TokenExchange() error = %v", err)
		}
		for _, candidate := range []string{
			"https://evil.example/bye",
			logoutURI + "/../evil",
			redirectURI, // registered for authorization, not for logout
		} {
			_, err := deploy.client.Logout(ctx, tokens.IDToken, candidate, "")
			refused(t, "logout to "+candidate, err, "invalid_post_logout_redirect_uri")
		}
	})

	t.Run("discovery endpoints", func(t *testing.T) {
		// A discovery document pointing elsewhere is how a relying party gets
		// walked onto an attacker's token endpoint.
		for _, candidate := range []string{
			"https://evil.example/token",
			"//evil.example/token",
			"http://id.example/token",
		} {
			_, err := deploy.client.Discovery(ctx, discoveryWithTokenEndpoint(candidate))
			refused(t, "discovery advertising "+candidate, err, "invalid_request")
		}
	})
}

// TestCSRF covers the values that bind a flow to the party that started it.
func TestCSRF(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	t.Run("state is echoed unchanged", func(t *testing.T) {
		response := deploy.authorize(t, session)
		if response.State != "client-state" {
			t.Fatalf("state = %q; a client cannot match its own CSRF token", response.State)
		}
	})

	t.Run("PKCE cannot be downgraded", func(t *testing.T) {
		request := authorizationRequest(deploy)
		request.CodeChallengeMethod = "plain"
		request.CodeChallenge = verifier
		_, err := deploy.client.Authorize(ctx, request)
		if err == nil {
			t.Fatal("the authorization endpoint accepted plain PKCE")
		}

		request = authorizationRequest(deploy)
		request.CodeChallenge = ""
		request.CodeChallengeMethod = ""
		if _, err := deploy.client.Authorize(ctx, request); err == nil {
			t.Fatal("the authorization endpoint accepted a request with no PKCE")
		}
	})

	t.Run("a code cannot be redeemed without its verifier", func(t *testing.T) {
		response := deploy.authorize(t, session)
		request := deploy.tokenRequest(response.Code)
		request.CodeVerifier = strings.Repeat("z", len(verifier))
		_, err := deploy.client.TokenExchange(ctx, request)
		refused(t, "code redemption with a wrong PKCE verifier", err, "invalid_grant")
	})

	t.Run("the interaction secret is required", func(t *testing.T) {
		started, err := deploy.client.Authorize(ctx, authorizationRequest(deploy))
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}
		// Knowing the interaction ID is not enough; a leaked identifier in a
		// log is inert without its secret half.
		_, err = deploy.client.InteractionComplete(ctx, started.InteractionID, "guessed",
			session.SessionID, session.Secret)
		refused(t, "interaction completion without the handle secret", err, "interaction_not_found")
	})
}

// TestCrossTenantSubstitution covers one tenant's credentials being presented
// against another tenant's objects.
func TestCrossTenantSubstitution(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// A second tenant with its own principal and session.
	other, err := deploy.client.TenantBootstrap(ctx, "other-tenant")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	strangerIdentifier := sesame.PrincipalIdentifier{Namespace: "email", Value: "stranger@example.com"}
	stranger, err := deploy.client.PrincipalCreate(ctx, other.Tenant.ID, "human", strangerIdentifier)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := deploy.client.SetPassword(ctx, stranger.ID, password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	begun, err := deploy.client.AuthenticationBegin(ctx, other.Tenant.ID, strangerIdentifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := deploy.client.AuthenticationVerifyPassword(ctx, begun.TransactionID, password); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	strangerSession, err := deploy.client.AuthenticationComplete(ctx, begun.TransactionID, 0)
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	t.Run("a foreign session completes an interaction", func(t *testing.T) {
		started, err := deploy.client.Authorize(ctx, authorizationRequest(deploy))
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}
		_, err = deploy.client.InteractionComplete(ctx, started.InteractionID, started.Secret,
			strangerSession.SessionID, strangerSession.Secret)
		refused(t, "interaction completion with another tenant's session", err, "session_not_found")
	})

	t.Run("a decision under a foreign session", func(t *testing.T) {
		decision, err := deploy.client.Decide(ctx, sesame.DecisionRequest{
			TenantID:      deploy.tenantID,
			SessionID:     strangerSession.SessionID,
			SessionSecret: strangerSession.Secret,
			Action:        "doc:read",
			Resource:      "project:one",
		}, nil)
		if err != nil {
			t.Fatalf("Decide() error = %v", err)
		}
		if decision.Decision != "deny" {
			t.Fatalf("a cross-tenant session decided %q", decision.Decision)
		}
	})

	t.Run("a foreign identifier in the wrong tenant", func(t *testing.T) {
		// Beginning against the wrong tenant must not resolve the principal,
		// and must not say so either.
		begun, err := deploy.client.AuthenticationBegin(ctx, deploy.tenantID, strangerIdentifier)
		if err != nil {
			t.Fatalf("AuthenticationBegin() error = %v", err)
		}
		result, err := deploy.client.AuthenticationVerifyPassword(ctx, begun.TransactionID, password)
		if err != nil {
			t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
		}
		if result.Assurance != "" {
			t.Fatal("an identifier from another tenant authenticated")
		}
	})
}

// TestRecoveryCannotBypassAssurance is a named Phase 4 exit criterion: a
// recovery code is a backup for the second step, not a way to skip the first.
func TestRecoveryCannotBypassAssurance(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	codes, err := deploy.client.RecoveryCodesIssue(ctx, deploy.principalID)
	if err != nil {
		t.Fatalf("RecoveryCodesIssue() error = %v", err)
	}
	if len(codes.Codes) == 0 {
		t.Fatal("no recovery codes were issued")
	}

	// Straight to a recovery code with no first factor.
	begun, err := deploy.client.AuthenticationBegin(ctx, deploy.tenantID, deploy.identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	_, err = deploy.client.AuthenticationVerifyRecoveryCode(ctx, begun.TransactionID, codes.Codes[0])
	refused(t, "recovery code without a first factor", err, "transaction_closed")

	// The code was not spent by the refused attempt: it still works after a
	// password.
	second, err := deploy.client.AuthenticationBegin(ctx, deploy.tenantID, deploy.identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := deploy.client.AuthenticationVerifyPassword(ctx, second.TransactionID, password); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	result, err := deploy.client.AuthenticationVerifyRecoveryCode(ctx, second.TransactionID, codes.Codes[0])
	if err != nil {
		t.Fatalf("AuthenticationVerifyRecoveryCode() error = %v", err)
	}
	if result.Assurance != "mfa" {
		t.Fatalf("assurance = %q, want mfa", result.Assurance)
	}

	// And it is single use.
	third, err := deploy.client.AuthenticationBegin(ctx, deploy.tenantID, deploy.identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := deploy.client.AuthenticationVerifyPassword(ctx, third.TransactionID, password); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	spent, err := deploy.client.AuthenticationVerifyRecoveryCode(ctx, third.TransactionID, codes.Codes[0])
	if err != nil {
		t.Fatalf("AuthenticationVerifyRecoveryCode() error = %v", err)
	}
	if spent.Assurance == "mfa" {
		t.Fatal("a spent recovery code was accepted a second time")
	}
}

// TestAlgorithmConfusion covers the classic JWT failure at the real boundary.
func TestAlgorithmConfusion(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	response := deploy.authorize(t, session)
	tokens, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code))
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}

	segments := strings.Split(tokens.IDToken, ".")
	if len(segments) != 3 {
		t.Fatalf("ID token is not a compact JWS: %q", tokens.IDToken)
	}
	for name, header := range map[string]string{
		"alg none":    `{"alg":"none","typ":"JWT"}`,
		"alg HS256":   `{"alg":"HS256","typ":"JWT"}`,
		"unknown kid": `{"alg":"ES256","typ":"JWT","kid":"someone-else"}`,
	} {
		forged := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + segments[1] + "." + segments[2]
		_, err := deploy.client.Logout(ctx, forged, "", "")
		refused(t, "logout with a "+name+" hint", err, "invalid_logout_hint")
	}

	// The discovery document must not advertise anything that would invite
	// the attempt in the first place.
	metadata, err := deploy.client.Discovery(ctx, sesame.DiscoveryEndpoints{})
	if err != nil {
		t.Fatalf("Discovery() error = %v", err)
	}
	for _, advertised := range metadata.IDTokenSigningAlgValuesSupported {
		if advertised == "none" || advertised == "HS256" {
			t.Fatalf("discovery advertises %q", advertised)
		}
	}
}

// TestIdentifierEnumeration covers whether an outsider can learn which
// accounts exist.
func TestIdentifierEnumeration(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	known, err := deploy.client.AuthenticationBegin(ctx, deploy.tenantID, deploy.identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	unknown, err := deploy.client.AuthenticationBegin(ctx, deploy.tenantID,
		sesame.PrincipalIdentifier{Namespace: "email", Value: "nobody@example.com"})
	if err != nil {
		t.Fatalf("AuthenticationBegin() for an unknown identifier error = %v", err)
	}
	if known.State != unknown.State {
		t.Fatalf("a known identifier reported state %q and an unknown one %q", known.State, unknown.State)
	}

	knownResult, err := deploy.client.AuthenticationVerifyPassword(ctx, known.TransactionID, "wrong")
	if err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	unknownResult, err := deploy.client.AuthenticationVerifyPassword(ctx, unknown.TransactionID, "wrong")
	if err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	if knownResult.State != unknownResult.State ||
		knownResult.FailureCode != unknownResult.FailureCode ||
		knownResult.AttemptsLeft != unknownResult.AttemptsLeft {
		t.Fatalf("a wrong password distinguishes a known identifier: %#v vs %#v",
			knownResult, unknownResult)
	}
}

// TestSuspensionAndRevocationBiteImmediately covers whether a live credential
// survives the administrative action that was supposed to end it.
func TestSuspensionAndRevocationBiteImmediately(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	response := deploy.authorize(t, session)
	tokens, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code))
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}

	if _, err := deploy.client.PrincipalSuspend(ctx, deploy.principalID); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}
	// The access token still verifies cryptographically; introspection is
	// where the suspension shows up, which is why a resource server must ask.
	result, err := deploy.client.Introspect(ctx, deploy.clientID, deploy.secret, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if result.Active {
		t.Fatal("a suspended principal's access token introspects as active")
	}
	_, err = deploy.client.TokenExchange(ctx, sesameRefresh(deploy, tokens.RefreshToken))
	refused(t, "refresh after suspension", err, "invalid_grant")
	if _, err := deploy.client.SessionVerify(ctx, session.SessionID, session.Secret); err == nil {
		t.Fatal("a suspended principal's session still verifies")
	}
}

// TestDisabledClientCannotAuthorize covers the client half of the same
// question.
func TestDisabledClientCannotAuthorize(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	response := deploy.authorize(t, session)
	if err := deploy.client.ClientDisable(ctx, deploy.clientID, "incident"); err != nil {
		t.Fatalf("ClientDisable() error = %v", err)
	}

	// A code already in flight is worthless once the client is disabled.
	_, err := deploy.client.TokenExchange(ctx, deploy.tokenRequest(response.Code))
	refused(t, "code redemption by a disabled client", err, "client_not_found")
	// And no new flow starts. A disabled client is reported exactly as an
	// unknown one, so the endpoint does not enumerate registrations.
	_, err = deploy.client.Authorize(ctx, authorizationRequest(deploy))
	refused(t, "authorization by a disabled client", err, "client_not_found")
}

func authorizationRequest(deploy *deployment) sesame.AuthorizationRequest {
	return sesame.AuthorizationRequest{
		ClientID:            deploy.clientID,
		RedirectURI:         redirectURI,
		ResponseType:        "code",
		Scopes:              []string{"openid", "offline_access"},
		State:               "client-state",
		Nonce:               "client-nonce",
		CodeChallenge:       challenge(),
		CodeChallengeMethod: "S256",
	}
}

func sesameRefresh(deploy *deployment, token string) sesame.TokenRequest {
	return sesame.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: token,
		ClientID:     deploy.clientID,
		ClientSecret: deploy.secret,
	}
}

func discoveryWithTokenEndpoint(tokenEndpoint string) sesame.DiscoveryEndpoints {
	return sesame.DiscoveryEndpoints{TokenEndpoint: tokenEndpoint}
}
