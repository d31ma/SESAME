package machine

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	"github.com/d31ma/sesame/internal/domain/saml/samltest"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

const (
	edgeSAMLEntityID = "https://idp.example.com/metadata"
	edgeSAMLSSOURL   = "https://idp.example.com/sso"
	edgeSAMLConsumer = "https://app.example/saml/acs"
	edgeSAMLAudience = "https://sesame.example"
)

// samlEdge builds a processor with one registered SAML provider.
func samlEdge(t *testing.T) (*Processor, *samltest.Signer, string, string, time.Time) {
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
	service.UseIssuer(edgeSAMLAudience)
	now := time.Unix(1_700_000_000, 0).UTC()
	service.UseClock(func() time.Time { return now })
	processor := New(system.New(buildinfo.New("", "", "")), service)

	tenant, err := service.Bootstrap(context.Background(), "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	signer, err := samltest.NewSigner("idp.example.com")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	registered := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"saml-1","operation":"saml.provider_register",`+
			`"parameters":{"tenant_id":"`+tenant.Tenant.ID+`","name":"Corp SSO","entity_id":"`+
			edgeSAMLEntityID+`","sso_url":"`+edgeSAMLSSOURL+`","certificates":[`+
			jsonString(t, signer.PEM)+`],"identifier_namespace":"email",`+
			`"linking":"verified_email"}}`)
	if !registered[0].OK {
		t.Fatalf("saml.provider_register failed: %+v", registered[0].Error)
	}
	var provider struct {
		ID string `json:"provider_id"`
	}
	decodeResult(t, registered[0].Result, &provider)
	return processor, signer, tenant.Tenant.ID, provider.ID, now
}

// samlLoginStart drives login_start and returns what the host would send.
func samlLoginStart(t *testing.T, processor *Processor, tenantID, providerID string) (string, string) {
	t.Helper()

	started := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"saml-2","operation":"saml.login_start",`+
			`"parameters":{"tenant_id":"`+tenantID+`","provider_id":"`+providerID+
			`","consumer_url":"`+edgeSAMLConsumer+`"}}`)
	if !started[0].OK {
		t.Fatalf("saml.login_start failed: %+v", started[0].Error)
	}
	var login struct {
		LoginID      string `json:"login_id"`
		RequestID    string `json:"request_id"`
		AuthnRequest string `json:"authn_request"`
		Destination  string `json:"destination"`
	}
	decodeResult(t, started[0].Result, &login)
	if login.Destination != edgeSAMLSSOURL {
		t.Fatalf("destination = %q", login.Destination)
	}
	if login.AuthnRequest == "" {
		t.Fatal("login_start returned no AuthnRequest for the host to send")
	}
	return login.LoginID, login.RequestID
}

// TestSAMLEdgeCompletesALogin is the whole slice through the wire: register,
// start, and complete with a genuinely signed assertion.
func TestSAMLEdgeCompletesALogin(t *testing.T) {
	t.Parallel()

	processor, signer, tenantID, providerID, now := samlEdge(t)
	loginID, requestID := samlLoginStart(t, processor, tenantID, providerID)

	response, err := signer.SignedResponse(samltest.Assertion{
		ID:           "_edge-1",
		Issuer:       edgeSAMLEntityID,
		Subject:      "alice@example.com",
		Audience:     edgeSAMLAudience,
		Recipient:    edgeSAMLConsumer,
		RequestID:    requestID,
		NotBefore:    now.Add(-time.Minute),
		NotOnOrAfter: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("SignedResponse() error = %v", err)
	}

	completed := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"saml-3","operation":"saml.login_complete",`+
			`"parameters":{"tenant_id":"`+tenantID+`","login_id":"`+loginID+
			`","assertion":`+jsonString(t, response)+`}}`)
	if !completed[0].OK {
		t.Fatalf("saml.login_complete failed: %+v", completed[0].Error)
	}
	var result struct {
		PrincipalID string `json:"principal_id"`
		Provisioned bool   `json:"provisioned"`
		Session     struct {
			SessionID string `json:"session_id"`
			Secret    string `json:"session_secret"`
		} `json:"session"`
	}
	decodeResult(t, completed[0].Result, &result)
	if result.PrincipalID == "" || !result.Provisioned || result.Session.Secret == "" {
		t.Fatalf("login_complete returned %#v", result)
	}
}

// TestSAMLEdgeRefusalsCarryStableCodes pins the wire codes. Callers branch on
// these, so a change here is a compatibility break, and the rejected-assertion
// code must stay one value for every way an assertion can fail.
func TestSAMLEdgeRefusalsCarryStableCodes(t *testing.T) {
	t.Parallel()

	processor, signer, tenantID, providerID, now := samlEdge(t)
	loginID, requestID := samlLoginStart(t, processor, tenantID, providerID)

	wrongAudience, err := signer.SignedResponse(samltest.Assertion{
		ID:           "_edge-2",
		Issuer:       edgeSAMLEntityID,
		Subject:      "alice@example.com",
		Audience:     "https://evil.example/sp",
		Recipient:    edgeSAMLConsumer,
		RequestID:    requestID,
		NotBefore:    now.Add(-time.Minute),
		NotOnOrAfter: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("SignedResponse() error = %v", err)
	}

	cases := []struct {
		name    string
		request string
		code    string
	}{
		{
			name: "an unknown provider",
			request: `{"protocol_version":"1","request_id":"e1","operation":"saml.provider_get",` +
				`"parameters":{"tenant_id":"` + tenantID + `","provider_id":"sam_` +
				`00000000000000000000000000000000"}}`,
			code: ErrorSAMLProviderNotFound,
		},
		{
			name: "an unknown login",
			request: `{"protocol_version":"1","request_id":"e2","operation":"saml.login_complete",` +
				`"parameters":{"tenant_id":"` + tenantID + `","login_id":"sal_` +
				`00000000000000000000000000000000","assertion":"PHI+PC9yPg=="}}`,
			code: ErrorSAMLLoginNotFound,
		},
		{
			// An assertion written for a different service provider must be
			// refused with the same opaque code as every other failure.
			name: "an assertion for another service provider",
			request: `{"protocol_version":"1","request_id":"e3","operation":"saml.login_complete",` +
				`"parameters":{"tenant_id":"` + tenantID + `","login_id":"` + loginID +
				`","assertion":` + jsonString(t, wrongAudience) + `}}`,
			code: ErrorSAMLAssertionRejected,
		},
		{
			// A response that is not even base64 must not reach the parser
			// and must not look different from a rejected assertion.
			name: "a response that is not base64",
			request: `{"protocol_version":"1","request_id":"e4","operation":"saml.login_complete",` +
				`"parameters":{"tenant_id":"` + tenantID + `","login_id":"` + loginID +
				`","assertion":"!!!not base64!!!"}}`,
			code: ErrorSAMLAssertionRejected,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			responses := runRequests(t, processor, testCase.request)
			if responses[0].OK {
				t.Fatalf("the request succeeded: %+v", responses[0].Result)
			}
			if responses[0].Error.Code != testCase.code {
				t.Fatalf("error code = %q, want %q", responses[0].Error.Code, testCase.code)
			}
		})
	}
}

// TestSAMLEdgeDisablesAProvider: disablement must be visible at the wire the
// moment it is recorded.
func TestSAMLEdgeDisablesAProvider(t *testing.T) {
	t.Parallel()

	processor, _, tenantID, providerID, _ := samlEdge(t)
	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"d1","operation":"saml.provider_disable",`+
			`"parameters":{"tenant_id":"`+tenantID+`","provider_id":"`+providerID+
			`","reason":"contract ended"}}`,
		`{"protocol_version":"1","request_id":"d2","operation":"saml.login_start",`+
			`"parameters":{"tenant_id":"`+tenantID+`","provider_id":"`+providerID+
			`","consumer_url":"`+edgeSAMLConsumer+`"}}`)
	if !responses[0].OK {
		t.Fatalf("saml.provider_disable failed: %+v", responses[0].Error)
	}
	if responses[1].OK {
		t.Fatal("a disabled provider still started a login")
	}
	if responses[1].Error.Code != ErrorSAMLProviderNotFound {
		t.Fatalf("error code = %q, want %q", responses[1].Error.Code, ErrorSAMLProviderNotFound)
	}
}

// TestSAMLEdgeRefusesWithoutStorage: every SAML operation needs a FYLO root,
// and none may quietly succeed against nothing.
func TestSAMLEdgeRefusesWithoutStorage(t *testing.T) {
	t.Parallel()

	processor := New(system.New(buildinfo.New("", "", "")), nil)
	for _, operation := range []string{
		"saml.provider_register", "saml.provider_get", "saml.provider_disable",
		"saml.login_start", "saml.login_complete",
	} {
		responses := runRequests(t, processor,
			`{"protocol_version":"1","request_id":"s1","operation":"`+operation+
				`","parameters":{}}`)
		if responses[0].OK {
			t.Fatalf("%s succeeded with no storage configured", operation)
		}
		if responses[0].Error.Code != ErrorStorageNotConfigured {
			t.Fatalf("%s error code = %q, want %q", operation,
				responses[0].Error.Code, ErrorStorageNotConfigured)
		}
	}
}
