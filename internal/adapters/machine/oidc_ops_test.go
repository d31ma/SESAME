package machine

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	"github.com/d31ma/sesame/internal/domain/token"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

const (
	edgeVerifier = "sesame-edge-verifier-0123456789-abcdefghijklmnopq"
	edgePassword = "correct horse battery staple"
	edgeRedirect = "https://app.example/cb"
)

func edgeChallenge() string {
	sum := sha256.Sum256([]byte(edgeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestAuthorizationCodeFlowThroughMachineEdge drives the whole browser flow
// as a host would: authorize, log the user in, complete the interaction, then
// redeem the code on the back channel.
func TestAuthorizationCodeFlowThroughMachineEdge(t *testing.T) {
	t.Parallel()

	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	key, err := token.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	service.UseSigningKey(key)
	service.UseIssuer("https://id.example")
	processor := New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, err := service.Bootstrap(ctx, "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, edgePassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "billing", "confidential",
		[]string{edgeRedirect}, nil, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	begun, _ := service.AuthenticationBegin(ctx, tenant.Tenant.ID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID, edgePassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}

	authorized := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"az-1","operation":"oidc.authorize","parameters":{"client_id":"`+registered.Client.ID+
			`","redirect_uri":"`+edgeRedirect+`","response_type":"code","scopes":["openid"],"state":"csrf","nonce":"n0","code_challenge":"`+
			edgeChallenge()+`","code_challenge_method":"S256"}}`,
		`{"protocol_version":"1","request_id":"az-2","operation":"oidc.authorize","parameters":{"client_id":"`+registered.Client.ID+
			`","redirect_uri":"https://evil.example/cb","response_type":"code","scopes":["openid"],"code_challenge":"`+
			edgeChallenge()+`","code_challenge_method":"S256"}}`,
	)
	if !authorized[0].OK {
		t.Fatalf("oidc.authorize response = %#v", authorized[0])
	}
	if authorized[1].OK || authorized[1].Error.Code != ErrorInvalidRedirectURI {
		t.Fatalf("unregistered redirect = %#v, want %s", authorized[1], ErrorInvalidRedirectURI)
	}

	var started identity.StartedInteraction
	if err := json.Unmarshal(mustMarshal(t, authorized[0].Result), &started); err != nil {
		t.Fatalf("decode interaction: %v", err)
	}

	completed := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"ic-1","operation":"oidc.interaction_complete","parameters":{"interaction_id":"`+
			started.InteractionID+`","interaction_secret":"wrong","session_id":"`+session.SessionID+`","session_secret":"`+session.Secret+`"}}`,
		`{"protocol_version":"1","request_id":"ic-2","operation":"oidc.interaction_complete","parameters":{"interaction_id":"`+
			started.InteractionID+`","interaction_secret":"`+started.Secret+`","session_id":"`+session.SessionID+`","session_secret":"`+session.Secret+`"}}`,
	)
	if completed[0].OK || completed[0].Error.Code != ErrorInteractionNotFound {
		t.Fatalf("wrong handle secret = %#v, want %s", completed[0], ErrorInteractionNotFound)
	}
	if !completed[1].OK {
		t.Fatalf("oidc.interaction_complete response = %#v", completed[1])
	}
	var response identity.AuthorizationResponse
	if err := json.Unmarshal(mustMarshal(t, completed[1].Result), &response); err != nil {
		t.Fatalf("decode authorization response: %v", err)
	}
	if response.RedirectURI != edgeRedirect || response.State != "csrf" {
		t.Fatalf("authorization response = %#v", response)
	}

	tokenRequest := func(id, verifier string) string {
		return `{"protocol_version":"1","request_id":"` + id + `","operation":"oidc.token","parameters":{"grant_type":"authorization_code","code":"` +
			response.Code + `","redirect_uri":"` + edgeRedirect + `","client_id":"` + registered.Client.ID +
			`","client_secret":"` + registered.Secret + `","code_verifier":"` + verifier + `"}}`
	}
	exchanged := runRequests(t, processor,
		tokenRequest("tk-1", strings.Repeat("z", len(edgeVerifier))),
		tokenRequest("tk-2", edgeVerifier),
		tokenRequest("tk-3", edgeVerifier),
	)
	if exchanged[0].OK || exchanged[0].Error.Code != ErrorInvalidGrant {
		t.Fatalf("wrong verifier = %#v, want %s", exchanged[0], ErrorInvalidGrant)
	}
	if !exchanged[1].OK {
		t.Fatalf("oidc.token response = %#v", exchanged[1])
	}
	// A replayed code is refused, and with the same code as every other way
	// a grant can be wrong.
	if exchanged[2].OK || exchanged[2].Error.Code != ErrorInvalidGrant {
		t.Fatalf("code replay = %#v, want %s", exchanged[2], ErrorInvalidGrant)
	}

	var tokens identity.TokenResponse
	if err := json.Unmarshal(mustMarshal(t, exchanged[1].Result), &tokens); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	claims, _, err := key.Verify(tokens.AccessToken, "https://id.example", registered.Client.ID, time.Now())
	if err != nil || claims.Subject != principal.ID {
		t.Fatalf("access token = %#v, %v", claims, err)
	}

	// The interaction record is inspectable without exposing either digest.
	inspected := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"ig-1","operation":"oidc.interaction_get","parameters":{"interaction_id":"`+started.InteractionID+`"}}`,
	)[0]
	body := string(mustMarshal(t, inspected.Result))
	if !inspected.OK || strings.Contains(body, "digest") || strings.Contains(body, started.Secret) {
		t.Fatalf("oidc.interaction_get = %s", body)
	}
}

// TestRefreshRotationThroughMachineEdge drives a rotating family over the
// wire, including the reuse detection that kills it.
func TestRefreshRotationThroughMachineEdge(t *testing.T) {
	t.Parallel()

	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	key, err := token.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	service.UseSigningKey(key)
	service.UseIssuer("https://id.example")
	processor := New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, err := service.Bootstrap(ctx, "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, edgePassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "offline", "confidential",
		[]string{edgeRedirect}, []string{"offline_access"}, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	begun, _ := service.AuthenticationBegin(ctx, tenant.Tenant.ID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID, edgePassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	started, err := service.AuthorizationStart(ctx, identity.AuthorizationRequest{
		ClientID:            registered.Client.ID,
		RedirectURI:         edgeRedirect,
		ResponseType:        "code",
		Scopes:              []string{"offline_access"},
		CodeChallenge:       edgeChallenge(),
		CodeChallengeMethod: "S256",
	}, "test")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	authorized, err := service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		session.SessionID, session.Secret, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}

	exchanged := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"tk-1","operation":"oidc.token","parameters":{"grant_type":"authorization_code","code":"`+
			authorized.Code+`","redirect_uri":"`+edgeRedirect+`","client_id":"`+registered.Client.ID+
			`","client_secret":"`+registered.Secret+`","code_verifier":"`+edgeVerifier+`"}}`,
	)[0]
	if !exchanged.OK {
		t.Fatalf("oidc.token response = %#v", exchanged)
	}
	var tokens identity.TokenResponse
	if err := json.Unmarshal(mustMarshal(t, exchanged.Result), &tokens); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("offline_access produced no refresh token")
	}

	refresh := func(id, value string) Response {
		return runRequests(t, processor,
			`{"protocol_version":"1","request_id":"`+id+`","operation":"oidc.token","parameters":{"grant_type":"refresh_token","refresh_token":"`+
				value+`","client_id":"`+registered.Client.ID+`","client_secret":"`+registered.Secret+`"}}`,
		)[0]
	}

	rotated := refresh("rf-1", tokens.RefreshToken)
	if !rotated.OK {
		t.Fatalf("refresh grant response = %#v", rotated)
	}
	var next identity.TokenResponse
	if err := json.Unmarshal(mustMarshal(t, rotated.Result), &next); err != nil {
		t.Fatalf("decode rotated tokens: %v", err)
	}
	if next.RefreshToken == tokens.RefreshToken {
		t.Fatal("the refresh grant did not rotate over the wire")
	}

	// Reuse of the spent token kills the family, taking the live successor
	// with it.
	if reused := refresh("rf-2", tokens.RefreshToken); reused.OK || reused.Error.Code != ErrorInvalidGrant {
		t.Fatalf("reused token = %#v, want %s", reused, ErrorInvalidGrant)
	}
	if successor := refresh("rf-3", next.RefreshToken); successor.OK || successor.Error.Code != ErrorInvalidGrant {
		t.Fatalf("successor after reuse = %#v, want %s", successor, ErrorInvalidGrant)
	}

	unknown := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fr-1","operation":"oidc.refresh_family_revoke","parameters":{"family_id":"rfm_00000000000000000000000000000000"}}`,
	)[0]
	if unknown.OK || unknown.Error.Code != ErrorRefreshFamilyMissing {
		t.Fatalf("unknown family = %#v, want %s", unknown, ErrorRefreshFamilyMissing)
	}
}

func TestDiscoveryAndIntrospectionThroughMachineEdge(t *testing.T) {
	t.Parallel()

	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	key, _ := token.NewSigningKey()
	service.UseSigningKey(key)
	service.UseIssuer("https://id.example")
	processor := New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, err := service.Bootstrap(ctx, "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, edgePassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "billing", "confidential",
		[]string{edgeRedirect}, nil, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	discovered := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"dc-1","operation":"oidc.discovery","parameters":{}}`,
		`{"protocol_version":"1","request_id":"dc-2","operation":"oidc.discovery","parameters":{"token_endpoint":"https://evil.example/token"}}`,
	)
	if !discovered[0].OK {
		t.Fatalf("oidc.discovery response = %#v", discovered[0])
	}
	if discovered[1].OK || discovered[1].Error.Code != ErrorInvalidRequest {
		t.Fatalf("off-origin endpoint = %#v, want %s", discovered[1], ErrorInvalidRequest)
	}
	var metadata oidcdomain.Metadata
	if err := json.Unmarshal(mustMarshal(t, discovered[0].Result), &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if metadata.Issuer != "https://id.example" || metadata.TokenEndpoint != "https://id.example/token" {
		t.Fatalf("metadata = %#v", metadata)
	}
	// The published document must not advertise anything the engine refuses.
	for _, grant := range metadata.GrantTypesSupported {
		if err := oidcdomain.ValidateGrantType(grant); err != nil {
			t.Fatalf("advertised grant %q is refused by the engine: %v", grant, err)
		}
	}

	// Run one login through to an access token, then introspect it.
	begun, _ := service.AuthenticationBegin(ctx, tenant.Tenant.ID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID, edgePassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	started, err := service.AuthorizationStart(ctx, identity.AuthorizationRequest{
		ClientID:            registered.Client.ID,
		RedirectURI:         edgeRedirect,
		ResponseType:        "code",
		Scopes:              []string{"openid"},
		CodeChallenge:       edgeChallenge(),
		CodeChallengeMethod: "S256",
	}, "test")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}
	authorized, err := service.AuthorizationComplete(ctx, started.InteractionID, started.Secret,
		session.SessionID, session.Secret, "test")
	if err != nil {
		t.Fatalf("AuthorizationComplete() error = %v", err)
	}
	tokens, err := service.TokenExchange(ctx, identity.TokenRequest{
		GrantType:    "authorization_code",
		Code:         authorized.Code,
		RedirectURI:  edgeRedirect,
		ClientID:     registered.Client.ID,
		ClientSecret: registered.Secret,
		CodeVerifier: edgeVerifier,
	}, "test")
	if err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}

	introspect := func(id, value string) Response {
		return runRequests(t, processor,
			`{"protocol_version":"1","request_id":"`+id+`","operation":"oidc.introspect","parameters":{"token":"`+
				value+`","client_id":"`+registered.Client.ID+`","client_secret":"`+registered.Secret+`"}}`,
		)[0]
	}

	live := introspect("in-1", tokens.AccessToken)
	if !live.OK {
		t.Fatalf("oidc.introspect response = %#v", live)
	}
	var active identity.Introspection
	if err := json.Unmarshal(mustMarshal(t, live.Result), &active); err != nil {
		t.Fatalf("decode introspection: %v", err)
	}
	if !active.Active || active.Subject != principal.ID {
		t.Fatalf("introspection = %#v", active)
	}

	// Revoking the session makes the very same token dead, which is the
	// whole reason a resource server introspects instead of only verifying.
	if err := service.SessionRevoke(ctx, session.SessionID, "signed out", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	dead := introspect("in-2", tokens.AccessToken)
	body := string(mustMarshal(t, dead.Result))
	if !dead.OK || !strings.Contains(body, `"active":false`) || strings.Contains(body, principal.ID) {
		t.Fatalf("revoked introspection = %s", body)
	}

	// Revocation acknowledges a token it can do nothing about, rather than
	// confirming it is unknown.
	acknowledged := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"rv-1","operation":"oidc.revoke","parameters":{"token":"nonsense","client_id":"`+
			registered.Client.ID+`","client_secret":"`+registered.Secret+`"}}`,
	)[0]
	if !acknowledged.OK || !strings.Contains(string(mustMarshal(t, acknowledged.Result)), `"acknowledged":true`) {
		t.Fatalf("oidc.revoke response = %#v", acknowledged)
	}
}

// TestConsentGateThroughMachineEdge drives the gap this closes: a third-party
// client is refused a code until the user agrees, and the refusal is a
// distinct code the host can act on rather than a generic failure.
func TestConsentGateThroughMachineEdge(t *testing.T) {
	t.Parallel()

	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	key, _ := token.NewSigningKey()
	service.UseSigningKey(key)
	service.UseIssuer("https://id.example")
	processor := New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, err := service.Bootstrap(ctx, "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, edgePassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}

	// An omitted audience takes the stricter rule.
	registered := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"cr-1","operation":"oidc_client.register","parameters":{"tenant_id":"`+
			tenant.Tenant.ID+`","name":"third-party","client_type":"confidential","redirect_uris":["`+edgeRedirect+`"]}}`,
	)[0]
	if !registered.OK {
		t.Fatalf("oidc_client.register response = %#v", registered)
	}
	var registration identity.ClientRegistration
	if err := json.Unmarshal(mustMarshal(t, registered.Result), &registration); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	if registration.Client.Audience != oidcdomain.AudienceThirdParty {
		t.Fatalf("an omitted audience defaulted to %q", registration.Client.Audience)
	}

	begun, _ := service.AuthenticationBegin(ctx, tenant.Tenant.ID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID, edgePassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	started, err := service.AuthorizationStart(ctx, identity.AuthorizationRequest{
		ClientID:            registration.Client.ID,
		RedirectURI:         edgeRedirect,
		ResponseType:        "code",
		Scopes:              []string{"openid"},
		CodeChallenge:       edgeChallenge(),
		CodeChallengeMethod: "S256",
	}, "test")
	if err != nil {
		t.Fatalf("AuthorizationStart() error = %v", err)
	}

	complete := func(id string) Response {
		return runRequests(t, processor,
			`{"protocol_version":"1","request_id":"`+id+`","operation":"oidc.interaction_complete","parameters":{"interaction_id":"`+
				started.InteractionID+`","interaction_secret":"`+started.Secret+`","session_id":"`+session.SessionID+
				`","session_secret":"`+session.Secret+`"}}`,
		)[0]
	}

	blocked := complete("ic-1")
	if blocked.OK || blocked.Error.Code != ErrorConsentRequired {
		t.Fatalf("third-party completion = %#v, want %s", blocked, ErrorConsentRequired)
	}

	granted := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"cg-1","operation":"oidc.consent_grant","parameters":{"session_id":"`+
			session.SessionID+`","session_secret":"`+session.Secret+`","client_id":"`+registration.Client.ID+
			`","scopes":["openid"]}}`,
		`{"protocol_version":"1","request_id":"cg-2","operation":"oidc.consent_grant","parameters":{"session_id":"`+
			session.SessionID+`","session_secret":"wrong","client_id":"`+registration.Client.ID+`","scopes":["openid"]}}`,
	)
	if !granted[0].OK {
		t.Fatalf("oidc.consent_grant response = %#v", granted[0])
	}
	// Consent needs the agreeing principal's own session.
	if granted[1].OK || granted[1].Error.Code != ErrorSessionNotFound {
		t.Fatalf("consent with a wrong session = %#v, want %s", granted[1], ErrorSessionNotFound)
	}

	if allowed := complete("ic-2"); !allowed.OK {
		t.Fatalf("completion after consent = %#v", allowed)
	}

	withdrawn := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"cw-1","operation":"oidc.consent_withdraw","parameters":{"principal_id":"`+
			principal.ID+`","client_id":"`+registration.Client.ID+`"}}`,
		`{"protocol_version":"1","request_id":"cg-3","operation":"oidc.consent_get","parameters":{"principal_id":"`+
			principal.ID+`","client_id":"`+registration.Client.ID+`"}}`,
	)
	if !withdrawn[0].OK {
		t.Fatalf("oidc.consent_withdraw response = %#v", withdrawn[0])
	}
	if !strings.Contains(string(mustMarshal(t, withdrawn[1].Result)), `"withdrawn":true`) {
		t.Fatalf("oidc.consent_get after withdrawal = %s", mustMarshal(t, withdrawn[1].Result))
	}
}

func TestTokenExchangeFailsClosedWithoutAnIssuer(t *testing.T) {
	t.Parallel()

	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	key, _ := token.NewSigningKey()
	service.UseSigningKey(key)
	processor := New(system.New(buildinfo.New("", "", "")), service)

	// No issuer configured: the engine refuses to mint rather than inventing
	// an issuer identifier from the request.
	response := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"tk-0","operation":"oidc.token","parameters":{"grant_type":"authorization_code","code":"int_00000000000000000000000000000000.x","redirect_uri":"`+
			edgeRedirect+`","client_id":"cli_00000000000000000000000000000000","code_verifier":"`+edgeVerifier+`"}}`,
	)[0]
	if response.OK || response.Error.Code != ErrorIssuerNotConfigured {
		t.Fatalf("response = %#v, want %s", response, ErrorIssuerNotConfigured)
	}
}
