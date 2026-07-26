package machine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

const (
	pushedPassword    = "correct horse battery staple"
	pushedVerifier    = "sesame-pushed-verifier-0123456789-abcdefghijk"
	pushedRedirectURI = "https://app.example/cb"
)

func pushedChallenge() string {
	sum := sha256.Sum256([]byte(pushedVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pushedEdge builds a processor with a confidential client able to push.
func pushedEdge(t *testing.T) (processor *Processor, clientID, clientSecret,
	sessionID, sessionSecret string) {
	t.Helper()

	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	key := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate secrets key: %v", err)
	}
	service.UseSecretsKey(key)
	signing, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	service.UseSigningKey(signing)
	service.UseIssuer("https://id.example")
	processor = New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, err := service.Bootstrap(ctx, "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID,
		principaldomain.KindHuman, identifier, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, pushedPassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "pushing-app",
		oidcdomain.TypeConfidential, []string{pushedRedirectURI},
		[]string{"profile"}, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	begun, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID,
		pushedPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := service.AuthenticationComplete(ctx, begun.TransactionID, 0, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	return processor, registered.Client.ID, registered.Secret, session.SessionID, session.Secret
}

// pushRequest pushes one valid authorization request and returns its
// reference.
func pushRequest(t *testing.T, processor *Processor, clientID, clientSecret, id string) string {
	t.Helper()

	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"`+id+`","operation":"oidc.pushed_authorize",`+
			`"parameters":{"client_id":"`+clientID+
			`","client_secret":`+jsonString(t, clientSecret)+
			`,"redirect_uri":"`+pushedRedirectURI+
			`","response_type":"code","scopes":["profile"],`+
			`"state":"client-state","nonce":"client-nonce",`+
			`"code_challenge":"`+pushedChallenge()+`","code_challenge_method":"S256"}}`)
	if !responses[0].OK {
		t.Fatalf("pushed_authorize failed: %+v", responses[0].Error)
	}
	var pushed struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	decodeResult(t, responses[0].Result, &pushed)
	if pushed.RequestURI == "" || pushed.ExpiresIn <= 0 {
		t.Fatalf("pushed_authorize returned %#v", pushed)
	}
	return pushed.RequestURI
}

// TestPushedEdgeWalksTheWholeFlow: a pushed request carries an ordinary code
// flow to tokens, with nothing but the reference crossing the browser.
func TestPushedEdgeWalksTheWholeFlow(t *testing.T) {
	t.Parallel()

	processor, clientID, clientSecret, sessionID, sessionSecret := pushedEdge(t)
	requestURI := pushRequest(t, processor, clientID, clientSecret, "p1")

	started := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"p2","operation":"oidc.authorize",`+
			`"parameters":{"client_id":"`+clientID+
			`","request_uri":`+jsonString(t, requestURI)+`}}`)
	if !started[0].OK {
		t.Fatalf("authorize by reference failed: %+v", started[0].Error)
	}
	var interaction struct {
		InteractionID string   `json:"interaction_id"`
		Secret        string   `json:"interaction_secret"`
		Scopes        []string `json:"scopes"`
	}
	decodeResult(t, started[0].Result, &interaction)
	if len(interaction.Scopes) == 0 {
		t.Fatalf("the pushed request's scopes were lost: %#v", interaction)
	}

	completed := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"p3","operation":"oidc.interaction_complete",`+
			`"parameters":{"interaction_id":"`+interaction.InteractionID+
			`","interaction_secret":`+jsonString(t, interaction.Secret)+
			`,"session_id":"`+sessionID+
			`","session_secret":`+jsonString(t, sessionSecret)+`}}`)
	if !completed[0].OK {
		t.Fatalf("interaction_complete failed: %+v", completed[0].Error)
	}
	var authorization struct {
		Code        string `json:"code"`
		State       string `json:"state"`
		RedirectURI string `json:"redirect_uri"`
	}
	decodeResult(t, completed[0].Result, &authorization)
	// Both came from the pushed request; neither was ever in the browser's
	// hands to be edited.
	if authorization.State != "client-state" {
		t.Fatalf("state = %q, want the pushed one", authorization.State)
	}
	if authorization.RedirectURI != pushedRedirectURI {
		t.Fatalf("redirect_uri = %q, want the pushed one", authorization.RedirectURI)
	}

	tokens := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"p4","operation":"oidc.token",`+
			`"parameters":{"grant_type":"authorization_code","code":`+
			jsonString(t, authorization.Code)+
			`,"redirect_uri":"`+pushedRedirectURI+
			`","client_id":"`+clientID+
			`","client_secret":`+jsonString(t, clientSecret)+
			`,"code_verifier":`+jsonString(t, pushedVerifier)+`}}`)
	if !tokens[0].OK {
		t.Fatalf("a pushed flow issued no tokens: %+v", tokens[0].Error)
	}
}

// TestPushedEdgeCodesAreStable. A host maps these to HTTP status and to an
// OAuth error at its own boundary, so renaming one is a wire-visible break.
func TestPushedEdgeCodesAreStable(t *testing.T) {
	t.Parallel()

	processor, clientID, clientSecret, _, _ := pushedEdge(t)
	requestURI := pushRequest(t, processor, clientID, clientSecret, "c1")

	t.Run("a reference beside loose parameters conflicts", func(t *testing.T) {
		responses := runRequests(t, processor,
			`{"protocol_version":"1","request_id":"c2","operation":"oidc.authorize",`+
				`"parameters":{"client_id":"`+clientID+
				`","request_uri":`+jsonString(t, requestURI)+
				`,"scopes":["profile","admin"]}}`)
		if responses[0].OK {
			t.Fatal("the authorization endpoint merged loose parameters into a pushed request")
		}
		if responses[0].Error.Code != ErrorRequestURIConflict {
			t.Fatalf("error code = %q, want %q", responses[0].Error.Code, ErrorRequestURIConflict)
		}
	})

	t.Run("an unknown reference is not found", func(t *testing.T) {
		responses := runRequests(t, processor,
			`{"protocol_version":"1","request_id":"c3","operation":"oidc.authorize",`+
				`"parameters":{"client_id":"`+clientID+
				`","request_uri":"`+oidcdomain.RequestURIPrefix+
				`par_00000000000000000000000000000000"}}`)
		if responses[0].OK {
			t.Fatal("the authorization endpoint accepted a reference it never issued")
		}
		if responses[0].Error.Code != ErrorRequestURINotFound {
			t.Fatalf("error code = %q, want %q", responses[0].Error.Code, ErrorRequestURINotFound)
		}
	})

	t.Run("a spent reference is not found", func(t *testing.T) {
		body := `{"protocol_version":"1","request_id":"c4","operation":"oidc.authorize",` +
			`"parameters":{"client_id":"` + clientID +
			`","request_uri":` + jsonString(t, requestURI) + `}}`
		if first := runRequests(t, processor, body); !first[0].OK {
			t.Fatalf("authorize by reference failed: %+v", first[0].Error)
		}
		responses := runRequests(t, processor, body)
		if responses[0].OK {
			t.Fatal("a spent reference was redeemed twice")
		}
		if responses[0].Error.Code != ErrorRequestURINotFound {
			t.Fatalf("error code = %q, want %q", responses[0].Error.Code, ErrorRequestURINotFound)
		}
	})
}

// TestPushedEdgeRefusesWithoutStorage. Fail closed: an engine with no FYLO
// root must refuse rather than push a request nowhere.
func TestPushedEdgeRefusesWithoutStorage(t *testing.T) {
	t.Parallel()

	processor := New(system.New(buildinfo.New("", "", "")), nil)
	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"s1","operation":"oidc.pushed_authorize",`+
			`"parameters":{"client_id":"cli_00000000000000000000000000000000"}}`)
	if responses[0].OK {
		t.Fatal("pushed_authorize succeeded without storage")
	}
	if responses[0].Error.Code != ErrorStorageNotConfigured {
		t.Fatalf("error code = %q, want %q", responses[0].Error.Code, ErrorStorageNotConfigured)
	}
}
