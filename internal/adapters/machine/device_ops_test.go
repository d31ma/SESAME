package machine

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

const devicePassword = "correct horse battery staple"

// deviceEdge builds a processor with a client registered for the device grant
// and a person able to approve it.
func deviceEdge(t *testing.T) (*Processor, string, string, string, string) {
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
	processor := New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, err := service.Bootstrap(ctx, "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "tv@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, devicePassword, "test"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "living-room-tv",
		oidcdomain.TypePublic, []string{"https://tv.example/cb"},
		[]string{"profile"}, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	begun, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID,
		principaldomain.Identifier{Namespace: "email", Value: "tv@example.com"}, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID,
		devicePassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	return processor, tenant.Tenant.ID, registered.Client.ID, session.SessionID, session.Secret
}

// TestDeviceEdgeWalksTheWholeGrant drives RFC 8628 through the wire: start,
// look up the typed code, approve, then poll successfully.
func TestDeviceEdgeWalksTheWholeGrant(t *testing.T) {
	t.Parallel()

	processor, tenantID, clientID, sessionID, sessionSecret := deviceEdge(t)

	started := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d1","operation":"oidc.device_authorize",`+
			`"parameters":{"client_id":"`+clientID+`","scopes":["profile"]}}`)
	if !started[0].OK {
		t.Fatalf("device_authorize failed: %+v", started[0].Error)
	}
	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		Interval   int    `json:"interval"`
		ExpiresIn  int64  `json:"expires_in"`
	}
	decodeResult(t, started[0].Result, &device)
	if device.DeviceCode == "" || device.UserCode == "" || device.Interval == 0 {
		t.Fatalf("device_authorize returned %#v", device)
	}

	// The verification surface shows what is being asked for, by the code a
	// person actually typed — lower case and without the separator.
	typed := "  " + device.UserCode[:4] + device.UserCode[5:] + " "
	looked := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d2","operation":"oidc.device_lookup",`+
			`"parameters":{"tenant_id":"`+tenantID+`","user_code":`+jsonString(t, typed)+`}}`)
	if !looked[0].OK {
		t.Fatalf("device_lookup failed: %+v", looked[0].Error)
	}

	approved := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d3","operation":"oidc.device_approve",`+
			`"parameters":{"tenant_id":"`+tenantID+`","user_code":"`+device.UserCode+
			`","session_id":"`+sessionID+`","session_secret":`+jsonString(t, sessionSecret)+`}}`)
	if !approved[0].OK {
		t.Fatalf("device_approve failed: %+v", approved[0].Error)
	}

	tokens := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d4","operation":"oidc.token",`+
			`"parameters":{"grant_type":"`+oidcdomain.GrantTypeDeviceCode+
			`","device_code":`+jsonString(t, device.DeviceCode)+
			`,"client_id":"`+clientID+`"}}`)
	if !tokens[0].OK {
		t.Fatalf("the device grant issued no tokens after approval: %+v", tokens[0].Error)
	}
	var issued struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
	}
	decodeResult(t, tokens[0].Result, &issued)
	if issued.AccessToken == "" || issued.IDToken == "" || issued.TokenType != "Bearer" {
		t.Fatalf("device grant returned %#v", issued)
	}

	// Single use: the same code must not buy a second set.
	replay := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d5","operation":"oidc.token",`+
			`"parameters":{"grant_type":"`+oidcdomain.GrantTypeDeviceCode+
			`","device_code":`+jsonString(t, device.DeviceCode)+
			`,"client_id":"`+clientID+`"}}`)
	if replay[0].OK {
		t.Fatal("a replayed device code bought a second token set")
	}
}

// TestDeviceEdgePollingCodesAreRFC8628Spelled pins the three token-endpoint
// outcomes. Device libraries branch on these exact strings, so inventing
// SESAME names for them would make every off-the-shelf client wrong.
func TestDeviceEdgePollingCodesAreRFC8628Spelled(t *testing.T) {
	t.Parallel()

	processor, tenantID, clientID, _, _ := deviceEdge(t)
	started := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"p1","operation":"oidc.device_authorize",`+
			`"parameters":{"client_id":"`+clientID+`","scopes":["profile"]}}`)
	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	decodeResult(t, started[0].Result, &device)

	poll := func(id string) Response {
		return runRequests(t, processor,
			`{"protocol_version":"1","request_id":"`+id+`","operation":"oidc.token",`+
				`"parameters":{"grant_type":"`+oidcdomain.GrantTypeDeviceCode+
				`","device_code":`+jsonString(t, device.DeviceCode)+
				`,"client_id":"`+clientID+`"}}`)[0]
	}

	// Nobody has approved it yet.
	pending := poll("p2")
	if pending.OK || pending.Error.Code != ErrorAuthorizationPending {
		t.Fatalf("pending poll = %+v, want %q", pending.Error, ErrorAuthorizationPending)
	}

	// A refusal is terminal and opaque.
	denied := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"p3","operation":"oidc.device_deny",`+
			`"parameters":{"tenant_id":"`+tenantID+`","user_code":"`+device.UserCode+`"}}`)
	if !denied[0].OK {
		t.Fatalf("device_deny failed: %+v", denied[0].Error)
	}
	refused := poll("p4")
	if refused.OK || refused.Error.Code != ErrorAccessDenied {
		t.Fatalf("denied poll = %+v, want %q", refused.Error, ErrorAccessDenied)
	}
}

// TestDeviceEdgeRefusesUnknownUserCodes: the verification surface must not
// become a way to enumerate pending devices.
func TestDeviceEdgeRefusesUnknownUserCodes(t *testing.T) {
	t.Parallel()

	processor, tenantID, _, sessionID, sessionSecret := deviceEdge(t)

	for name, request := range map[string]string{
		"lookup": `{"protocol_version":"1","request_id":"u1","operation":"oidc.device_lookup",` +
			`"parameters":{"tenant_id":"` + tenantID + `","user_code":"ABCD-EFGH"}}`,
		"approve": `{"protocol_version":"1","request_id":"u2","operation":"oidc.device_approve",` +
			`"parameters":{"tenant_id":"` + tenantID + `","user_code":"ABCD-EFGH",` +
			`"session_id":"` + sessionID + `","session_secret":` + jsonString(t, sessionSecret) + `}}`,
		"deny": `{"protocol_version":"1","request_id":"u3","operation":"oidc.device_deny",` +
			`"parameters":{"tenant_id":"` + tenantID + `","user_code":"ABCD-EFGH"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			responses := runRequests(t, processor, request)
			if responses[0].OK {
				t.Fatal("an unknown user code was accepted")
			}
			if responses[0].Error.Code != ErrorUserCodeNotFound {
				t.Fatalf("error code = %q, want %q", responses[0].Error.Code, ErrorUserCodeNotFound)
			}
		})
	}
}

// TestDeviceEdgeRefusesWithoutStorage: every device operation needs a FYLO
// root, and none may quietly succeed against nothing.
func TestDeviceEdgeRefusesWithoutStorage(t *testing.T) {
	t.Parallel()

	processor := New(system.New(buildinfo.New("", "", "")), nil)
	for _, operation := range []string{
		"oidc.device_authorize", "oidc.device_lookup",
		"oidc.device_approve", "oidc.device_deny",
	} {
		responses := runRequests(t, processor,
			`{"protocol_version":"1","request_id":"s1","operation":"`+operation+`","parameters":{}}`)
		if responses[0].OK {
			t.Fatalf("%s succeeded with no storage configured", operation)
		}
		if responses[0].Error.Code != ErrorStorageNotConfigured {
			t.Fatalf("%s error code = %q, want %q", operation,
				responses[0].Error.Code, ErrorStorageNotConfigured)
		}
	}
}
