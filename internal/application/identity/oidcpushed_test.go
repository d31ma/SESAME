package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

func (f *flowFixture) push(t *testing.T) PushedAuthorizationRequest {
	t.Helper()

	pushed, err := f.service.PushedAuthorizationStart(context.Background(),
		AuthorizationRequest{
			ClientID:            f.clientID,
			RedirectURI:         flowRedirectURI,
			ResponseType:        oidcdomain.ResponseTypeCode,
			Scopes:              []string{"profile"},
			State:               "client-state",
			Nonce:               "client-nonce",
			CodeChallenge:       flowChallenge(),
			CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
		}, f.secret, "test")
	if err != nil {
		t.Fatalf("PushedAuthorizationStart() error = %v", err)
	}
	return pushed
}

// TestPushedRequestCarriesTheWholeAuthorizationRequest is the happy path: what
// the browser carries is one opaque reference, and the interaction it starts
// is identical to one started from loose parameters.
func TestPushedRequestCarriesTheWholeAuthorizationRequest(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	pushed := fixture.push(t)

	if !strings.HasPrefix(pushed.RequestURI, oidcdomain.RequestURIPrefix) {
		t.Fatalf("request_uri = %q, want the RFC 9126 URN form", pushed.RequestURI)
	}
	if pushed.ExpiresIn <= 0 || pushed.ExpiresIn > 600 {
		t.Fatalf("expires_in = %d; a reference should live seconds, not minutes", pushed.ExpiresIn)
	}

	started, err := fixture.service.AuthorizationStart(context.Background(),
		AuthorizationRequest{ClientID: fixture.clientID, RequestURI: pushed.RequestURI}, "test")
	if err != nil {
		t.Fatalf("AuthorizationStart() from a reference error = %v", err)
	}
	// The scopes came from the pushed request, not from the browser.
	if len(started.Scopes) == 0 || started.Scopes[0] != "openid" {
		t.Fatalf("started scopes = %v; the pushed request's scopes were lost", started.Scopes)
	}
	if started.InteractionID == "" || started.Secret == "" {
		t.Fatalf("started = %#v", started)
	}
}

// TestPushedRequestIsSingleUse. A reference that survived its first use could
// be replayed by anything that saw the redirect — browser history, a referrer
// header, a proxy log.
func TestPushedRequestIsSingleUse(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	pushed := fixture.push(t)
	request := AuthorizationRequest{ClientID: fixture.clientID, RequestURI: pushed.RequestURI}

	if _, err := fixture.service.AuthorizationStart(context.Background(), request, "test"); err != nil {
		t.Fatalf("first AuthorizationStart() error = %v", err)
	}
	if _, err := fixture.service.AuthorizationStart(context.Background(), request,
		"test"); !errors.Is(err, ErrRequestURINotFound) {
		t.Fatalf("replayed request_uri: err = %v, want ErrRequestURINotFound", err)
	}
}

// TestPushedRequestRefusesLooseParameters is the property PAR exists for.
//
// RFC 9126 forbids merging, because honouring a redirect URI or scope set that
// arrived in the browser beside the reference would restore exactly the
// tampering the push removed. SESAME refuses rather than ignores, so a client
// that sends both finds out immediately.
func TestPushedRequestRefusesLooseParameters(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)

	for name, tamper := range map[string]func(*AuthorizationRequest){
		"a redirect URI":  func(r *AuthorizationRequest) { r.RedirectURI = "https://evil.example/cb" },
		"a response type": func(r *AuthorizationRequest) { r.ResponseType = oidcdomain.ResponseTypeCode },
		"scopes":          func(r *AuthorizationRequest) { r.Scopes = []string{"profile", "admin"} },
		"a state":         func(r *AuthorizationRequest) { r.State = "attacker-state" },
		"a nonce":         func(r *AuthorizationRequest) { r.Nonce = "attacker-nonce" },
		"a PKCE challenge": func(r *AuthorizationRequest) {
			r.CodeChallenge = flowChallenge()
			r.CodeChallengeMethod = oidcdomain.ChallengeMethodS256
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pushed := fixture.push(t)
			request := AuthorizationRequest{
				ClientID:   fixture.clientID,
				RequestURI: pushed.RequestURI,
			}
			tamper(&request)
			if _, err := fixture.service.AuthorizationStart(context.Background(), request,
				"test"); !errors.Is(err, ErrRequestURIConflict) {
				t.Fatalf("%s beside a reference: err = %v, want ErrRequestURIConflict", name, err)
			}
		})
	}
}

// TestPushedRequestIsBoundToItsClient: a second client quoting somebody else's
// reference must get the same answer as one quoting a reference that never
// existed.
func TestPushedRequestIsBoundToItsClient(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	pushed := fixture.push(t)

	other, err := fixture.service.ClientRegister(context.Background(), fixture.tenantID,
		"other-app", oidcdomain.TypeConfidential, []string{"https://other.example/cb"},
		[]string{"profile"}, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	if _, err := fixture.service.AuthorizationStart(context.Background(),
		AuthorizationRequest{ClientID: other.Client.ID, RequestURI: pushed.RequestURI},
		"test"); !errors.Is(err, ErrRequestURINotFound) {
		t.Fatalf("another client's request_uri: err = %v, want ErrRequestURINotFound", err)
	}
}

// TestPushedRequestExpires: the window is the gap between building a redirect
// and issuing it, which is seconds.
func TestPushedRequestExpires(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	pushed := fixture.push(t)
	fixture.now = fixture.now.Add(oidcdomain.PushedRequestLifetime + time.Second)

	if _, err := fixture.service.AuthorizationStart(context.Background(),
		AuthorizationRequest{ClientID: fixture.clientID, RequestURI: pushed.RequestURI},
		"test"); !errors.Is(err, ErrRequestURINotFound) {
		t.Fatalf("expired request_uri: err = %v, want ErrRequestURINotFound", err)
	}
}

// TestPushingRequiresClientAuthentication. Attributing the request to a client
// before a browser is involved is half of what PAR buys; an unauthenticated
// push would hand that away.
func TestPushingRequiresClientAuthentication(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	request := AuthorizationRequest{
		ClientID:            fixture.clientID,
		RedirectURI:         flowRedirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{"profile"},
		CodeChallenge:       flowChallenge(),
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}
	for name, secret := range map[string]string{
		"no secret":    "",
		"wrong secret": "not-the-secret",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := fixture.service.PushedAuthorizationStart(context.Background(),
				request, secret, "test"); err == nil {
				t.Fatal("a request was pushed without client authentication")
			}
		})
	}
}

// TestPushedRequestRejectsWhatTheAuthorizationEndpointWould: validating at
// push time and again at redemption must not disagree, or a client could push
// something the authorization endpoint would have refused.
func TestPushedRequestRejectsWhatTheAuthorizationEndpointWould(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	base := AuthorizationRequest{
		ClientID:            fixture.clientID,
		RedirectURI:         flowRedirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{"profile"},
		CodeChallenge:       flowChallenge(),
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}
	for name, tamper := range map[string]func(*AuthorizationRequest){
		"an unregistered redirect URI": func(r *AuthorizationRequest) {
			r.RedirectURI = "https://evil.example/cb"
		},
		"an unregistered scope": func(r *AuthorizationRequest) {
			r.Scopes = []string{"profile", "admin"}
		},
		"no PKCE challenge": func(r *AuthorizationRequest) {
			r.CodeChallenge, r.CodeChallengeMethod = "", ""
		},
		"a plain PKCE method": func(r *AuthorizationRequest) {
			r.CodeChallengeMethod = "plain"
		},
		"an implicit response type": func(r *AuthorizationRequest) {
			r.ResponseType = "token"
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := base
			tamper(&request)
			if _, err := fixture.service.PushedAuthorizationStart(context.Background(),
				request, fixture.secret, "test"); err == nil {
				t.Fatalf("the push accepted %s, which the authorization endpoint refuses", name)
			}
		})
	}
}

// TestSnapshotCarriesPushedRequests: the single-use claim has to survive a
// restart, or a reference becomes replayable by restarting the engine.
func TestSnapshotCarriesPushedRequests(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)

	pushed := fixture.push(t)
	request := AuthorizationRequest{ClientID: fixture.clientID, RequestURI: pushed.RequestURI}
	if _, err := fixture.service.AuthorizationStart(context.Background(), request, "test"); err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}

	restored, err := NewFromSnapshot(&memoryLedger{}, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	restored.UseIssuer(flowIssuer)
	restored.UseSigningKey(fixture.signingKey)
	restored.UseClock(func() time.Time { return fixture.now })

	if _, err := restored.AuthorizationStart(context.Background(), request,
		"test"); !errors.Is(err, ErrRequestURINotFound) {
		t.Fatalf("a restart forgot a spent request_uri: err = %v", err)
	}
}

// TestSpentReferencesAreRememberedForTheirWholeWindow guards the rule that
// decides which records a snapshot keeps.
//
// The rule is the deadline, not consumption. An earlier version dropped a
// spent reference as soon as it was spent, which reads as tidy and is the one
// record that must not go: inside its window, the spent marker is the only
// thing standing between a reference somebody observed in a redirect and a
// second redemption.
func TestSpentReferencesAreRememberedForTheirWholeWindow(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	pushed := fixture.push(t)
	request := AuthorizationRequest{ClientID: fixture.clientID, RequestURI: pushed.RequestURI}
	if _, err := fixture.service.AuthorizationStart(context.Background(), request, "test"); err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}

	fixture.service.mu.Lock()
	exported := fixture.service.exportPushedRequestsLocked()
	fixture.service.mu.Unlock()
	if len(exported) != 1 || !exported[0].Request.Consumed {
		t.Fatalf("a snapshot taken inside the window dropped the spent marker: %#v", exported)
	}
}

// TestPushedRequestsDoNotAccumulate: without pruning, every reference ever
// pushed stays in the projection — and in every snapshot taken from it — for
// the life of the process.
func TestPushedRequestsDoNotAccumulate(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	for range 3 {
		fixture.push(t)
	}
	fixture.service.mu.Lock()
	live := len(fixture.service.pushedRequests)
	fixture.service.mu.Unlock()
	if live != 3 {
		t.Fatalf("three live references, projection holds %d", live)
	}

	// Past the deadline neither a spent nor an unspent reference decides
	// anything: both are refused on time.
	fixture.now = fixture.now.Add(oidcdomain.PushedRequestLifetime + time.Second)
	fixture.push(t)

	fixture.service.mu.Lock()
	remaining := len(fixture.service.pushedRequests)
	exported := len(fixture.service.exportPushedRequestsLocked())
	fixture.service.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("expired references were kept: projection holds %d, want 1", remaining)
	}
	if exported != 1 {
		t.Fatalf("expired references reached a snapshot: exported %d, want 1", exported)
	}
}
