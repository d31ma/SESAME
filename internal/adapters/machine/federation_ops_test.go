package machine

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

const (
	edgeIssuer      = "https://idp.example.com"
	edgeIDPClientID = "sesame-at-idp"
	edgeCallback    = "https://app.example/federation/cb"
)

// edgeProvider is a stand-in OpenID Provider for the machine-edge tests.
type edgeProvider struct{ key *rsa.PrivateKey }

func newEdgeProvider(t *testing.T) *edgeProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate provider key: %v", err)
	}
	return &edgeProvider{key: key}
}

func (p *edgeProvider) discovery(t *testing.T) string {
	t.Helper()

	return jsonString(t, map[string]any{
		"issuer":                                edgeIssuer,
		"authorization_endpoint":                edgeIssuer + "/authorize",
		"token_endpoint":                        edgeIssuer + "/token",
		"jwks_uri":                              edgeIssuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *edgeProvider) keySet(t *testing.T) string {
	t.Helper()

	return jsonString(t, map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "idp-1",
		"n":   base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
	}}})
}

func jsonString(t *testing.T, value any) string {
	t.Helper()

	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// federationEdge builds a processor with one registered, configured provider.
func federationEdge(t *testing.T) (*Processor, *identity.Service, *edgeProvider, string, string) {
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
	processor := New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, err := service.Bootstrap(ctx, "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	idp := newEdgeProvider(t)

	registered := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-1","operation":"federation.provider_register",`+
			`"parameters":{"tenant_id":"`+tenant.Tenant.ID+`","name":"Corp SSO","issuer":"`+edgeIssuer+
			`","client_id":"`+edgeIDPClientID+`","client_secret":"idp-secret","scopes":["email"],`+
			`"subject_claim":"sub","email_claim":"email","linking":"verified_email"}}`)
	if !registered[0].OK {
		t.Fatalf("provider_register failed: %+v", registered[0].Error)
	}
	var payload struct {
		Provider struct {
			ID string `json:"provider_id"`
		} `json:"provider"`
		Fetch struct {
			URL    string `json:"url"`
			Method string `json:"method"`
		} `json:"fetch"`
	}
	decodeResult(t, registered[0].Result, &payload)
	// The engine names the URL. A host is never handed one a caller chose.
	if payload.Fetch.URL != edgeIssuer+"/.well-known/openid-configuration" {
		t.Fatalf("discovery URL = %q", payload.Fetch.URL)
	}
	if payload.Fetch.Method != "GET" {
		t.Fatalf("discovery method = %q", payload.Fetch.Method)
	}
	return processor, service, idp, tenant.Tenant.ID, payload.Provider.ID
}

func configureEdge(t *testing.T, processor *Processor, idp *edgeProvider, tenantID, providerID string) {
	t.Helper()

	configured := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-2","operation":"federation.provider_configure",`+
			`"parameters":{"tenant_id":"`+tenantID+`","provider_id":"`+providerID+
			`","discovery_document":`+jsonString(t, idp.discovery(t))+
			`,"key_set_document":`+jsonString(t, idp.keySet(t))+`}}`)
	if !configured[0].OK {
		t.Fatalf("provider_configure failed: %+v", configured[0].Error)
	}
}

// TestFederationEdgeStartsALogin covers login_start and the shape of what it
// hands the host.
//
// It stops short of completing the login. The nonce the engine sealed is not
// readable from this package, and exporting an accessor so a test could reach
// it would widen the service's API for the benefit of a test — the completion
// path is proven in the identity package, which can see its own internals.
func TestFederationEdgeStartsALogin(t *testing.T) {
	t.Parallel()

	processor, _, idp, tenantID, providerID := federationEdge(t)
	configureEdge(t, processor, idp, tenantID, providerID)

	started := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-3","operation":"federation.login_start",`+
			`"parameters":{"tenant_id":"`+tenantID+`","provider_id":"`+providerID+
			`","redirect_uri":"`+edgeCallback+`"}}`)
	if !started[0].OK {
		t.Fatalf("login_start failed: %+v", started[0].Error)
	}
	var login struct {
		LoginID          string `json:"login_id"`
		AuthorizationURL string `json:"authorization_url"`
	}
	decodeResult(t, started[0].Result, &login)
	if !strings.Contains(login.AuthorizationURL, "code_challenge_method=S256") {
		t.Fatalf("authorization URL carries no S256 challenge: %q", login.AuthorizationURL)
	}
	if !strings.HasPrefix(login.AuthorizationURL, edgeIssuer+"/authorize?") {
		t.Fatalf("authorization URL is not the provider's endpoint: %q", login.AuthorizationURL)
	}

	// login_exchange refuses a callback whose state does not match.
	exchanged := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-4","operation":"federation.login_exchange",`+
			`"parameters":{"tenant_id":"`+tenantID+`","login_id":"`+login.LoginID+
			`","state":"a-forged-state","code":"provider-code"}}`)
	if exchanged[0].OK {
		t.Fatal("login_exchange accepted a forged state")
	}
	if exchanged[0].Error.Code != ErrorAssertionRejected {
		t.Fatalf("code = %q, want %q", exchanged[0].Error.Code, ErrorAssertionRejected)
	}
}

// TestFederationEdgeRefusesAHostileDiscoveryDocument proves validation happens
// in the engine, not in whatever fetched the document.
func TestFederationEdgeRefusesAHostileDiscoveryDocument(t *testing.T) {
	t.Parallel()

	processor, _, idp, tenantID, providerID := federationEdge(t)

	hostile := jsonString(t, map[string]any{
		"issuer":                 edgeIssuer,
		"authorization_endpoint": edgeIssuer + "/authorize",
		"token_endpoint":         "https://evil.example.com/token",
		"jwks_uri":               edgeIssuer + "/jwks",
	})
	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-5","operation":"federation.provider_configure",`+
			`"parameters":{"tenant_id":"`+tenantID+`","provider_id":"`+providerID+
			`","discovery_document":`+jsonString(t, hostile)+
			`,"key_set_document":`+jsonString(t, idp.keySet(t))+`}}`)
	if responses[0].OK {
		t.Fatal("the edge accepted an off-origin token endpoint")
	}
	if !strings.Contains(responses[0].Error.Message, "token_endpoint") {
		t.Fatalf("error = %+v, want it to name the offending endpoint", responses[0].Error)
	}
}

// TestFederationEdgeRefusesAnUnconfiguredProvider fails closed: without
// validated metadata the engine does not know where to send anyone.
func TestFederationEdgeRefusesAnUnconfiguredProvider(t *testing.T) {
	t.Parallel()

	processor, _, _, tenantID, providerID := federationEdge(t)

	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-6","operation":"federation.login_start",`+
			`"parameters":{"tenant_id":"`+tenantID+`","provider_id":"`+providerID+
			`","redirect_uri":"`+edgeCallback+`"}}`)
	if responses[0].OK {
		t.Fatal("login_start succeeded against an unconfigured provider")
	}
	if responses[0].Error.Code != ErrorProviderNotConfigured {
		t.Fatalf("code = %q, want %q", responses[0].Error.Code, ErrorProviderNotConfigured)
	}
}

// TestFederationEdgeRejectionIsOpaque: every verification failure returns one
// code, so a caller cannot map out the flow by probing it.
func TestFederationEdgeRejectionIsOpaque(t *testing.T) {
	t.Parallel()

	processor, _, idp, tenantID, providerID := federationEdge(t)
	configureEdge(t, processor, idp, tenantID, providerID)

	started := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-7","operation":"federation.login_start",`+
			`"parameters":{"tenant_id":"`+tenantID+`","provider_id":"`+providerID+
			`","redirect_uri":"`+edgeCallback+`"}}`)
	var login struct {
		LoginID string `json:"login_id"`
	}
	decodeResult(t, started[0].Result, &login)

	// A well-formed assertion signed by the real provider, but minted with a
	// nonce that belongs to no login here.
	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-8","operation":"federation.login_complete",`+
			`"parameters":{"tenant_id":"`+tenantID+`","login_id":"`+login.LoginID+
			`","id_token":"`+idp.sign(t, "not-this-logins-nonce")+`"}}`)
	if responses[0].OK {
		t.Fatal("the edge accepted a replayed assertion")
	}
	if responses[0].Error.Code != ErrorAssertionRejected {
		t.Fatalf("code = %q, want %q", responses[0].Error.Code, ErrorAssertionRejected)
	}
	// The message must not describe which check failed.
	for _, leak := range []string{"nonce", "signature", "kid", "audience"} {
		if strings.Contains(strings.ToLower(responses[0].Error.Message), leak) {
			t.Fatalf("the refusal names %q: %q", leak, responses[0].Error.Message)
		}
	}
}

// TestFederationEdgeHidesAnotherTenantsProvider: cross-tenant access must be
// indistinguishable from a provider that does not exist.
func TestFederationEdgeHidesAnotherTenantsProvider(t *testing.T) {
	t.Parallel()

	processor, service, idp, tenantID, providerID := federationEdge(t)
	configureEdge(t, processor, idp, tenantID, providerID)

	other, err := service.Bootstrap(context.Background(), "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-9","operation":"federation.provider_get",`+
			`"parameters":{"tenant_id":"`+other.Tenant.ID+`","provider_id":"`+providerID+`"}}`)
	if responses[0].OK {
		t.Fatal("one tenant read another's provider")
	}
	if responses[0].Error.Code != ErrorProviderNotFound {
		t.Fatalf("code = %q, want %q", responses[0].Error.Code, ErrorProviderNotFound)
	}
}

// TestFederationEdgeProviderGetHidesTheClientSecret: the sealed secret must
// never reach a caller through a read operation.
func TestFederationEdgeProviderGetHidesTheClientSecret(t *testing.T) {
	t.Parallel()

	processor, _, idp, tenantID, providerID := federationEdge(t)
	configureEdge(t, processor, idp, tenantID, providerID)

	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"fed-10","operation":"federation.provider_get",`+
			`"parameters":{"tenant_id":"`+tenantID+`","provider_id":"`+providerID+`"}}`)
	if !responses[0].OK {
		t.Fatalf("provider_get failed: %+v", responses[0].Error)
	}
	if strings.Contains(jsonString(t, responses[0].Result), "idp-secret") {
		t.Fatal("provider_get returned the provider's client secret")
	}
	if !strings.Contains(jsonString(t, responses[0].Result), edgeIssuer+"/token") {
		t.Fatal("provider_get does not report the resolved token endpoint")
	}
}

// TestFederationOperationsRequireStorage covers the fail-closed path when no
// FYLO root is configured.
func TestFederationOperationsRequireStorage(t *testing.T) {
	t.Parallel()

	processor := New(system.New(buildinfo.New("", "", "")), nil)
	for _, operation := range []string{
		"federation.provider_register", "federation.provider_configure",
		"federation.provider_get", "federation.login_start",
		"federation.login_exchange", "federation.login_complete",
	} {
		responses := runRequests(t, processor,
			`{"protocol_version":"1","request_id":"fed-11","operation":"`+operation+
				`","parameters":{}}`)
		if responses[0].OK {
			t.Fatalf("%s succeeded with no storage configured", operation)
		}
		if responses[0].Error.Code != ErrorStorageNotConfigured {
			t.Fatalf("%s code = %q, want %q",
				operation, responses[0].Error.Code, ErrorStorageNotConfigured)
		}
	}
}

func (p *edgeProvider) sign(t *testing.T, nonce string) string {
	t.Helper()

	header := jsonString(t, map[string]string{"alg": "RS256", "kid": "idp-1"})
	claims := jsonString(t, map[string]any{
		"iss":            edgeIssuer,
		"sub":            "provider-subject-1",
		"aud":            edgeIDPClientID,
		"nonce":          nonce,
		"iat":            1_700_000_000,
		"exp":            9_999_999_999,
		"email":          "person@example.com",
		"email_verified": true,
	})
	signing := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(claims))
	sum := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// decodeResult re-encodes a decoded result so a test can read typed fields.
// Response.Result is `any` on the wire side, which is the right shape for a
// transport and the wrong one for an assertion.
func decodeResult(t *testing.T, result any, target any) {
	t.Helper()

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("re-encode result: %v", err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode result: %v", err)
	}
}
