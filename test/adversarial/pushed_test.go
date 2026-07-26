package adversarial_test

import (
	"context"
	"testing"

	"github.com/d31ma/sesame/clients/go/sesame"
)

// pushedRequest is the request this suite pushes: a valid one, so every
// refusal below is caused by the attack rather than by the request.
func pushedRequest(deploy *deployment) sesame.AuthorizationRequest {
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

// TestPushedRequestCannotBeTamperedWith is the attack PAR exists to stop.
//
// In a plain code flow every parameter travels through the user agent, so
// anything that can rewrite a URL — an extension, a malicious app handling the
// scheme, a person editing the address bar — can widen the scopes or move the
// redirect before the user ever sees a consent screen. Pushing the request
// removes the material; these cases prove the engine does not quietly hand it
// back.
func TestPushedRequestCannotBeTamperedWith(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// RFC 9126 says a client that sends both a request_uri and loose
	// parameters gets the pushed values; SESAME refuses instead. Ignoring
	// would be quieter and worse: a client could not tell whether the values
	// it sent had been used, and a proxy that appended one would look like it
	// had succeeded.
	for name, tamper := range map[string]func(*sesame.AuthorizationRequest){
		"widened scopes":      func(r *sesame.AuthorizationRequest) { r.Scopes = []string{"openid", "admin"} },
		"a moved redirect":    func(r *sesame.AuthorizationRequest) { r.RedirectURI = "https://evil.example/cb" },
		"the same redirect":   func(r *sesame.AuthorizationRequest) { r.RedirectURI = redirectURI },
		"a swapped state":     func(r *sesame.AuthorizationRequest) { r.State = "attacker-state" },
		"a swapped nonce":     func(r *sesame.AuthorizationRequest) { r.Nonce = "attacker-nonce" },
		"a downgraded method": func(r *sesame.AuthorizationRequest) { r.CodeChallengeMethod = "plain" },
		"a swapped challenge": func(r *sesame.AuthorizationRequest) { r.CodeChallenge = challenge() },
	} {
		t.Run(name, func(t *testing.T) {
			pushed, err := deploy.client.PushedAuthorizationStart(ctx, pushedRequest(deploy), deploy.secret)
			if err != nil {
				t.Fatalf("PushedAuthorizationStart() error = %v", err)
			}
			request := sesame.AuthorizationRequest{
				ClientID:   deploy.clientID,
				RequestURI: pushed.RequestURI,
			}
			tamper(&request)
			_, err = deploy.client.Authorize(ctx, request)
			refused(t, name+" beside a pushed reference", err, "request_uri_conflict")
		})
	}
}

// TestPushedReferenceIsNotABearerToken. The reference reaches the browser, so
// it reaches everything the browser touches: history, referrer headers, a
// corporate proxy's access log. What stops that mattering is that it is single
// use, client-bound, and short-lived — not that it is secret.
func TestPushedReferenceIsNotABearerToken(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	session := deploy.login(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	t.Run("a spent reference cannot be replayed", func(t *testing.T) {
		pushed, err := deploy.client.PushedAuthorizationStart(ctx, pushedRequest(deploy), deploy.secret)
		if err != nil {
			t.Fatalf("PushedAuthorizationStart() error = %v", err)
		}
		request := sesame.AuthorizationRequest{ClientID: deploy.clientID, RequestURI: pushed.RequestURI}
		started, err := deploy.client.Authorize(ctx, request)
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}
		if _, err := deploy.client.InteractionComplete(ctx, started.InteractionID, started.Secret,
			session.SessionID, session.Secret); err != nil {
			t.Fatalf("InteractionComplete() error = %v", err)
		}
		_, err = deploy.client.Authorize(ctx, request)
		refused(t, "a replayed request_uri", err, "request_uri_not_found")
	})

	t.Run("a reference is spent even when what follows fails", func(t *testing.T) {
		// The reference is consumed before the interaction exists. Spending it
		// only on success would leave a window in which a captured reference
		// is still live, which is the window an attacker wants.
		pushed, err := deploy.client.PushedAuthorizationStart(ctx, pushedRequest(deploy), deploy.secret)
		if err != nil {
			t.Fatalf("PushedAuthorizationStart() error = %v", err)
		}
		request := sesame.AuthorizationRequest{ClientID: deploy.clientID, RequestURI: pushed.RequestURI}
		if _, err := deploy.client.Authorize(ctx, request); err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}
		_, err = deploy.client.Authorize(ctx, request)
		refused(t, "a second use of a reference", err, "request_uri_not_found")
	})

	t.Run("a forged reference is refused", func(t *testing.T) {
		for _, candidate := range []string{
			"urn:ietf:params:oauth:request_uri:par_" + "00000000000000000000000000000000",
			"par_00000000000000000000000000000000",
			"urn:ietf:params:oauth:request_uri:",
			"https://id.example/par/00000000000000000000000000000000",
			"urn:ietf:params:oauth:request_uri:../par_0",
		} {
			_, err := deploy.client.Authorize(ctx, sesame.AuthorizationRequest{
				ClientID:   deploy.clientID,
				RequestURI: candidate,
			})
			if err == nil {
				t.Fatalf("the authorization endpoint accepted forged reference %q", candidate)
			}
		}
	})
}

// TestPushedRequestIsBoundToTheClientThatPushedIt. Without the binding, a
// second registered client could quote a reference it observed and run the
// flow as the first — the confused-deputy shape, moved to PAR.
func TestPushedRequestIsBoundToTheClientThatPushedIt(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	pushed, err := deploy.client.PushedAuthorizationStart(ctx, pushedRequest(deploy), deploy.secret)
	if err != nil {
		t.Fatalf("PushedAuthorizationStart() error = %v", err)
	}
	attacker, err := deploy.client.ClientRegister(ctx, deploy.tenantID, "attacker-app", "confidential",
		[]string{"https://evil.example/cb"}, []string{"profile"}, "first_party", nil)
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	_, err = deploy.client.Authorize(ctx, sesame.AuthorizationRequest{
		ClientID:   attacker.Client.ID,
		RequestURI: pushed.RequestURI,
	})
	// Refused as unknown rather than as somebody else's: telling the attacker
	// the reference exists would make the endpoint an oracle for whether a
	// given client is mid-flow.
	refused(t, "another client quoting a pushed reference", err, "request_uri_not_found")
}

// TestPushingRequiresClientAuthentication. Attributing the request to a client
// before a browser is involved is half of what PAR buys. An unauthenticated
// push would let anyone store a request under a confidential client's name.
func TestPushingRequiresClientAuthentication(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for name, secret := range map[string]string{
		"an unauthenticated push": "",
		"a wrong client secret":   "not-the-secret",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := deploy.client.PushedAuthorizationStart(ctx, pushedRequest(deploy), secret)
			// The same code an unknown client ID gets, over the same Argon2id
			// work: the push endpoint must not become the cheap oracle for
			// which client IDs are registered that the token endpoint refuses
			// to be.
			refused(t, name, err, "client_not_found")
		})
	}
}

// TestPushedRequestCannotSmuggleWhatTheAuthorizationEndpointRefuses. Two
// validation paths that disagree is how a rejected request gets in through the
// other door.
func TestPushedRequestCannotSmuggleWhatTheAuthorizationEndpointRefuses(t *testing.T) {
	t.Parallel()

	deploy := newDeployment(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for name, tamper := range map[string]func(*sesame.AuthorizationRequest){
		"an unregistered redirect": func(r *sesame.AuthorizationRequest) {
			r.RedirectURI = "https://evil.example/cb"
		},
		"a traversal redirect": func(r *sesame.AuthorizationRequest) {
			r.RedirectURI = redirectURI + "/../evil"
		},
		"an unregistered scope": func(r *sesame.AuthorizationRequest) {
			r.Scopes = []string{"openid", "admin"}
		},
		"no PKCE": func(r *sesame.AuthorizationRequest) {
			r.CodeChallenge, r.CodeChallengeMethod = "", ""
		},
		"plain PKCE": func(r *sesame.AuthorizationRequest) {
			r.CodeChallengeMethod = "plain"
		},
		"an implicit response type": func(r *sesame.AuthorizationRequest) {
			r.ResponseType = "token"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := pushedRequest(deploy)
			tamper(&request)
			if _, err := deploy.client.PushedAuthorizationStart(ctx, request,
				deploy.secret); err == nil {
				t.Fatalf("the push endpoint accepted %s, which the authorization endpoint refuses", name)
			}
		})
	}
}
