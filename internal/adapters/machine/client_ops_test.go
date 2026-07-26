package machine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

func TestOIDCClientLifecycleThroughMachineEdge(t *testing.T) {
	t.Parallel()

	tenantService, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	processor := New(system.New(buildinfo.New("", "", "")), tenantService)

	bootstrap := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"boot-1","operation":"tenant.bootstrap","parameters":{"name":"acme"}}`,
	)[0]
	var bootResult identity.BootstrapResult
	if err := json.Unmarshal(mustMarshal(t, bootstrap.Result), &bootResult); err != nil {
		t.Fatalf("decode bootstrap: %v", err)
	}
	tenantID := bootResult.Tenant.ID

	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"reg-1","operation":"oidc_client.register","parameters":{"tenant_id":"`+tenantID+`","name":"billing","client_type":"confidential","redirect_uris":["https://app.example/cb"],"scopes":["profile"]}}`,
		`{"protocol_version":"1","request_id":"reg-2","operation":"oidc_client.register","parameters":{"tenant_id":"`+tenantID+`","name":"billing","client_type":"public","redirect_uris":["https://app.example/cb"]}}`,
		`{"protocol_version":"1","request_id":"reg-3","operation":"oidc_client.register","parameters":{"tenant_id":"`+tenantID+`","name":"leaky","client_type":"public","redirect_uris":["https://*.example/cb"]}}`,
	)
	if !responses[0].OK {
		t.Fatalf("oidc_client.register response = %#v", responses[0])
	}
	if responses[1].OK || responses[1].Error.Code != ErrorClientExists {
		t.Fatalf("duplicate name response = %#v, want %s", responses[1], ErrorClientExists)
	}
	// A wildcard redirect is refused at the edge, not stored and matched
	// loosely later.
	if responses[2].OK || responses[2].Error.Code != ErrorInvalidRequest {
		t.Fatalf("wildcard redirect response = %#v, want %s", responses[2], ErrorInvalidRequest)
	}

	var registered identity.ClientRegistration
	if err := json.Unmarshal(mustMarshal(t, responses[0].Result), &registered); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	if registered.Secret == "" {
		t.Fatal("a confidential client registration returned no secret")
	}
	clientID := registered.Client.ID

	after := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"get-1","operation":"oidc_client.get","parameters":{"client_id":"`+clientID+`"}}`,
		`{"protocol_version":"1","request_id":"get-2","operation":"oidc_client.get","parameters":{"client_id":"cli_00000000000000000000000000000000"}}`,
		`{"protocol_version":"1","request_id":"rot-1","operation":"oidc_client.rotate_secret","parameters":{"client_id":"`+clientID+`"}}`,
		`{"protocol_version":"1","request_id":"dis-1","operation":"oidc_client.disable","parameters":{"client_id":"`+clientID+`","reason":"leaked"}}`,
		`{"protocol_version":"1","request_id":"rot-2","operation":"oidc_client.rotate_secret","parameters":{"client_id":"`+clientID+`"}}`,
	)
	// oidc_client.get never returns a secret or its verifier.
	fetched := string(mustMarshal(t, after[0].Result))
	if !after[0].OK || strings.Contains(fetched, registered.Secret) || strings.Contains(fetched, "verifier") {
		t.Fatalf("oidc_client.get = %s", fetched)
	}
	if after[1].OK || after[1].Error.Code != ErrorClientNotFound {
		t.Fatalf("unknown client response = %#v, want %s", after[1], ErrorClientNotFound)
	}
	if !after[2].OK {
		t.Fatalf("oidc_client.rotate_secret response = %#v", after[2])
	}
	if !after[3].OK {
		t.Fatalf("oidc_client.disable response = %#v", after[3])
	}
	if after[4].OK || after[4].Error.Code != ErrorClientDisabled {
		t.Fatalf("rotate after disable = %#v, want %s", after[4], ErrorClientDisabled)
	}
}
