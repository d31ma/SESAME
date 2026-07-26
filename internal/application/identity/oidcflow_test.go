package identity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

const (
	flowIssuer      = "https://id.example"
	flowRedirectURI = "https://app.example/cb"
	flowVerifier    = "sesame-test-verifier-0123456789-abcdefghijklmnop"
	flowPassword    = "correct horse battery staple"
)

type flowFixture struct {
	service     *Service
	ledger      *memoryLedger
	signingKey  *tokendomain.SigningKey
	tenantID    string
	principalID string
	clientID    string
	secret      string
	sessionID   string
	sessionKey  string
	now         time.Time
}

func flowChallenge() string {
	sum := sha256.Sum256([]byte(flowVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newFlowFixture(t *testing.T) *flowFixture {
	t.Helper()

	service, ledger, tenantID := bootstrapService(t)
	key, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	fixture := &flowFixture{
		service:    service,
		ledger:     ledger,
		signingKey: key,
		tenantID:   tenantID,
		now:        time.Unix(1_700_000_000, 0).UTC(),
	}
	service.UseSigningKey(key)
	service.UseIssuer(flowIssuer)
	service.UseClock(func() time.Time { return fixture.now })

	ctx := context.Background()
	principal, err := service.PrincipalCreate(ctx, tenantID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	fixture.principalID = principal.ID
	if err := service.PasswordSet(ctx, principal.ID, flowPassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}

	registered, err := service.ClientRegister(ctx, tenantID, "billing", oidcdomain.TypeConfidential,
		[]string{flowRedirectURI}, []string{"profile"}, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	fixture.clientID = registered.Client.ID
	fixture.secret = registered.Secret

	fixture.sessionID, fixture.sessionKey = fixture.login(t)
	return fixture
}

func (f *flowFixture) login(t *testing.T) (string, string) {
	t.Helper()

	ctx := context.Background()
	begun, err := f.service.AuthenticationBegin(ctx, f.tenantID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := f.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, flowPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	issued, err := f.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	return issued.SessionID, issued.Secret
}

func (f *flowFixture) authorize(t *testing.T) StartedInteraction {
	t.Helper()

	started, err := f.service.AuthorizationStart(context.Background(), AuthorizationRequest{
		ClientID:            f.clientID,
		RedirectURI:         flowRedirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{"profile"},
		State:               "client-csrf-token",
		Nonce:               "client-nonce",
		CodeChallenge:       flowChallenge(),
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}, "test")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	return started
}

func (f *flowFixture) tokenRequest(code string) TokenRequest {
	return TokenRequest{
		GrantType:    oidcdomain.GrantTypeAuthorizationCode,
		Code:         code,
		RedirectURI:  flowRedirectURI,
		ClientID:     f.clientID,
		ClientSecret: f.secret,
		CodeVerifier: flowVerifier,
	}
}

func TestAuthorizationCodeFlowEndToEnd(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()

	started := fixture.authorize(t)
	if started.Secret == "" || started.ClientName != "billing" ||
		strings.Join(started.Scopes, " ") != "openid profile" {
		t.Fatalf("started = %#v", started)
	}

	response, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	// The redirect URI comes from the validated interaction, not from
	// anything the completing caller supplied.
	if response.RedirectURI != flowRedirectURI || response.State != "client-csrf-token" || response.Code == "" {
		t.Fatalf("response = %#v", response)
	}

	tokens, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test")
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	if tokens.TokenType != "Bearer" || tokens.Scope != "openid profile" ||
		tokens.ExpiresIn != int64(AccessTokenLifetime.Seconds()) {
		t.Fatalf("tokens = %#v", tokens)
	}

	access, accessBody, err := fixture.signingKey.Verify(tokens.AccessToken, flowIssuer, fixture.clientID, fixture.now)
	if err != nil {
		t.Fatalf("access token does not verify: %v", err)
	}
	if access.Subject != fixture.principalID || accessBody["tenant_id"] != fixture.tenantID ||
		accessBody["sid"] != fixture.sessionID {
		t.Fatalf("access claims = %#v", accessBody)
	}
	idClaims, idBody, err := fixture.signingKey.Verify(tokens.IDToken, flowIssuer, fixture.clientID, fixture.now)
	if err != nil {
		t.Fatalf("ID token does not verify: %v", err)
	}
	// The nonce binds the ID token to the authorization request that asked
	// for it.
	if idClaims.Subject != fixture.principalID || idBody["nonce"] != "client-nonce" || idBody["acr"] != "password" {
		t.Fatalf("ID claims = %#v", idBody)
	}

	// The code is single use.
	if _, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("code replay error = %v, want ErrInvalidGrant", err)
	}
}

func TestAuthorizationStartRefusesUnregisteredInputs(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	base := AuthorizationRequest{
		ClientID:            fixture.clientID,
		RedirectURI:         flowRedirectURI,
		ResponseType:        oidcdomain.ResponseTypeCode,
		Scopes:              []string{"profile"},
		CodeChallenge:       flowChallenge(),
		CodeChallengeMethod: oidcdomain.ChallengeMethodS256,
	}

	cases := map[string]func(AuthorizationRequest) AuthorizationRequest{
		"unregistered redirect": func(r AuthorizationRequest) AuthorizationRequest {
			r.RedirectURI = "https://evil.example/cb"
			return r
		},
		"redirect with a suffix": func(r AuthorizationRequest) AuthorizationRequest {
			r.RedirectURI = flowRedirectURI + "/extra"
			return r
		},
		"unregistered scope": func(r AuthorizationRequest) AuthorizationRequest {
			r.Scopes = []string{"profile", "admin"}
			return r
		},
		"implicit flow": func(r AuthorizationRequest) AuthorizationRequest {
			r.ResponseType = "token"
			return r
		},
		"plain PKCE": func(r AuthorizationRequest) AuthorizationRequest {
			r.CodeChallengeMethod = "plain"
			r.CodeChallenge = flowVerifier
			return r
		},
		"no PKCE": func(r AuthorizationRequest) AuthorizationRequest {
			r.CodeChallenge = ""
			r.CodeChallengeMethod = ""
			return r
		},
		"unknown client": func(r AuthorizationRequest) AuthorizationRequest {
			r.ClientID = "cli_00000000000000000000000000000000"
			return r
		},
	}
	for label, mutate := range cases {
		if _, err := fixture.service.AuthorizationStart(ctx, mutate(base), "test"); err == nil {
			t.Fatalf("AuthorizationStart accepted %s", label)
		}
	}

	// A client disabled after registration authorizes nothing, and says so
	// the same way an unknown client does.
	if err := fixture.service.ClientDisable(ctx, fixture.clientID, "leaked", "test"); err != nil {
		t.Fatalf("ClientDisable() error = %v", err)
	}
	if _, err := fixture.service.AuthorizationStart(ctx, base, "test"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("AuthorizationStart with a disabled client error = %v", err)
	}
}

func TestAuthorizationCompleteRequiresTheRightProof(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	started := fixture.authorize(t)

	// The interaction ID alone is not enough: the handle secret is what
	// authorizes completing it, so an ID leaked through a log is inert.
	if _, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, "wrong",
		fixture.sessionID, fixture.sessionKey, "test"); !errors.Is(err, ErrInteractionNotFound) {
		t.Fatalf("wrong handle secret error = %v", err)
	}
	// A wrong session secret proves no authentication.
	if _, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, "wrong", "test"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("wrong session secret error = %v", err)
	}

	// A session from another tenant completes nothing, even with the right
	// handle secret.
	otherTenant, err := fixture.service.Bootstrap(ctx, "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	stranger, err := fixture.service.PrincipalCreate(ctx, otherTenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "stranger@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := fixture.service.PasswordSet(ctx, stranger.ID, flowPassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	begun, _ := fixture.service.AuthenticationBegin(ctx, otherTenant.Tenant.ID,
		principaldomain.Identifier{Namespace: "email", Value: "stranger@example.com"}, "test")
	if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, flowPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	crossTenant, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	if _, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		crossTenant.SessionID, crossTenant.Secret, "test"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("cross-tenant session error = %v", err)
	}

	// The genuine article works, and then the interaction is spent.
	if _, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test"); err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	if _, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test"); !errors.Is(err, ErrInteractionClosed) {
		t.Fatalf("second AuthorizationComplete error = %v", err)
	}
}

func TestAuthorizationExpiryIsEnforced(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()

	stale := fixture.authorize(t)
	fixture.now = fixture.now.Add(oidcdomain.InteractionLifetime + time.Second)
	if _, err := fixture.service.AuthorizationComplete(ctx, stale.InteractionID, stale.Secret,
		fixture.sessionID, fixture.sessionKey, "test"); !errors.Is(err, ErrInteractionClosed) {
		t.Fatalf("expired interaction error = %v", err)
	}

	fresh := fixture.authorize(t)
	response, err := fixture.service.AuthorizationComplete(ctx, fresh.InteractionID, fresh.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	// A code left sitting in browser history is worthless a minute later.
	fixture.now = fixture.now.Add(oidcdomain.CodeLifetime + time.Second)
	if _, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired code error = %v", err)
	}
}

func TestTokenExchangeRechecksEveryBinding(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	started := fixture.authorize(t)
	response, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}

	// A second client cannot redeem the first client's code, even with its
	// own valid credentials.
	other, err := fixture.service.ClientRegister(ctx, fixture.tenantID, "other", oidcdomain.TypeConfidential,
		[]string{flowRedirectURI}, nil, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	cases := map[string]func(TokenRequest) TokenRequest{
		"wrong verifier": func(r TokenRequest) TokenRequest {
			r.CodeVerifier = strings.Repeat("z", len(flowVerifier))
			return r
		},
		"absent verifier": func(r TokenRequest) TokenRequest {
			r.CodeVerifier = ""
			return r
		},
		"wrong redirect": func(r TokenRequest) TokenRequest {
			r.RedirectURI = "https://evil.example/cb"
			return r
		},
		"wrong client secret": func(r TokenRequest) TokenRequest {
			r.ClientSecret = "hunter2"
			return r
		},
		"absent client secret": func(r TokenRequest) TokenRequest {
			r.ClientSecret = ""
			return r
		},
		"another client": func(r TokenRequest) TokenRequest {
			r.ClientID = other.Client.ID
			r.ClientSecret = other.Secret
			return r
		},
		"refresh grant": func(r TokenRequest) TokenRequest {
			r.GrantType = "refresh_token"
			return r
		},
		"forged code": func(r TokenRequest) TokenRequest {
			r.Code = started.InteractionID + ".not-the-code"
			return r
		},
		"code without a handle": func(r TokenRequest) TokenRequest {
			r.Code = "nonsense"
			return r
		},
	}
	for label, mutate := range cases {
		if _, err := fixture.service.TokenExchange(ctx, mutate(fixture.tokenRequest(response.Code)), "test"); err == nil {
			t.Fatalf("TokenExchange accepted %s", label)
		}
	}

	// None of those attempts spent the code: the genuine request still works.
	if _, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test"); err != nil {
		t.Fatalf("TokenExchange() after failed attempts error = %v", err)
	}
}

func TestRevokedSessionStopsTheTokenExchange(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	started := fixture.authorize(t)
	response, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}

	// The code speaks for an authentication. Revoke it and the code is worth
	// nothing, even inside its own lifetime.
	if err := fixture.service.SessionRevoke(ctx, fixture.sessionID, "signed out", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	if _, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("revoked-session TokenExchange error = %v", err)
	}
}

func TestSuspendedPrincipalStopsTheTokenExchange(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	started := fixture.authorize(t)
	response, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}

	if _, err := fixture.service.PrincipalSuspend(ctx, fixture.principalID, "test"); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}
	if _, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("suspended-principal TokenExchange error = %v", err)
	}
}

func TestTokenIssuanceFailsClosedWithoutKeyOrIssuer(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	started := fixture.authorize(t)
	response, err := fixture.service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}

	fixture.service.UseIssuer("")
	if _, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test"); !errors.Is(err, ErrNoIssuer) {
		t.Fatalf("TokenExchange without an issuer error = %v", err)
	}
	fixture.service.UseIssuer(flowIssuer)
	fixture.service.UseSigningKey(nil)
	if _, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(response.Code), "test"); !errors.Is(err, tokendomain.ErrNoSigningKey) {
		t.Fatalf("TokenExchange without a signing key error = %v", err)
	}
}

// TestFlowStateSurvivesSnapshotAndReplay is the regression guard for a
// snapshot that forgets the interaction projection. A redeemed code must come
// back redeemed however the projection is rebuilt, or a restore would hand an
// attacker a second use of an intercepted code.
func TestFlowStateSurvivesSnapshotAndReplay(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)
	ctx := context.Background()

	spent := fixture.authorize(t)
	spentResponse, err := fixture.service.AuthorizationComplete(ctx, spent.InteractionID, spent.Secret,
		fixture.sessionID, fixture.sessionKey, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	if _, err := fixture.service.TokenExchange(ctx, fixture.tokenRequest(spentResponse.Code), "test"); err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	pending := fixture.authorize(t)

	rebuilt := map[string]*Service{}
	replayed, err := New(&memoryLedger{}, fixture.ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	rebuilt["replay"] = replayed
	seeded, err := NewFromSnapshot(&memoryLedger{}, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	rebuilt["snapshot"] = seeded

	for kind, restored := range rebuilt {
		restored.UseSigningKey(fixture.signingKey)
		restored.UseIssuer(flowIssuer)
		restored.UseClock(func() time.Time { return fixture.now })

		if _, err := restored.TokenExchange(ctx, fixture.tokenRequest(spentResponse.Code), "test"); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("%s: a spent code was redeemable again: %v", kind, err)
		}
		// The pending interaction is still completable, so the projection
		// carries live state rather than merely refusing everything.
		interaction, err := restored.InteractionGet(pending.InteractionID)
		if err != nil {
			t.Fatalf("%s: InteractionGet() error = %v", kind, err)
		}
		if interaction.Status != oidcdomain.InteractionAwaitingAuthentication ||
			interaction.SecretDigest != "" || interaction.CodeDigest != "" {
			t.Fatalf("%s: interaction = %#v", kind, interaction)
		}
	}

	// No bearer value reaches the snapshot or the ledger in usable form.
	encoded := string(snapshots.states[len(snapshots.states)-1])
	for _, value := range []string{spent.Secret, pending.Secret, spentResponse.Code, fixture.sessionKey} {
		if strings.Contains(encoded, value) {
			t.Fatal("the snapshot carries a plaintext bearer value")
		}
		for _, event := range fixture.ledger.events {
			if strings.Contains(string(event.Payload), value) {
				t.Fatalf("event %s carries a plaintext bearer value", event.Type)
			}
		}
	}
}
