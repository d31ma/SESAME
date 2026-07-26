package machine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	"github.com/d31ma/sesame/internal/domain/token"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

func TestTokenJWKSThroughMachineEdge(t *testing.T) {
	t.Parallel()

	tenantService, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	processor := New(system.New(buildinfo.New("", "", "")), tenantService)

	// Without a deployment key there is nothing to publish, and the engine
	// says so with a stable code rather than serving an empty key set that a
	// relying party would mistake for "this issuer signs nothing".
	response := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"jwks-0","operation":"token.jwks","parameters":{}}`,
	)[0]
	if response.OK || response.Error == nil || response.Error.Code != ErrorSigningNotConfigured {
		t.Fatalf("response = %#v, want %s", response, ErrorSigningNotConfigured)
	}

	key, err := token.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}
	tenantService.UseSigningKey(key)

	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"jwks-1","operation":"token.jwks","parameters":{}}`,
		`{"protocol_version":"1","request_id":"jwks-2","operation":"token.jwks","parameters":{"kid":"x"}}`,
	)
	if !responses[0].OK {
		t.Fatalf("token.jwks response = %#v", responses[0])
	}
	if responses[1].OK || responses[1].Error.Code != ErrorInvalidRequest {
		t.Fatalf("token.jwks with parameters = %#v", responses[1])
	}

	var published token.JWKS
	if err := json.Unmarshal(mustMarshal(t, responses[0].Result), &published); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(published.Keys) != 1 || published.Keys[0].KeyID != key.ID {
		t.Fatalf("published = %#v, want the deployment key %s", published, key.ID)
	}

	// The wire form must not carry the private scalar under any name.
	wire := string(mustMarshal(t, responses[0].Result))
	if strings.Contains(wire, `"d"`) {
		t.Fatalf("token.jwks published private material: %s", wire)
	}
}
