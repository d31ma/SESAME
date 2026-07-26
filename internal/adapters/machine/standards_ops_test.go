package machine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	"github.com/d31ma/sesame/internal/domain/token"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

func TestStandardsDispatchStartsOnlyValidatedAuthorizationInteractions(t *testing.T) {
	t.Parallel()

	processor, registered := standardsProcessor(t)
	base := map[string]any{
		"contract_version": "1",
		"endpoint":         "oidc.authorization",
		"method":           "GET",
		"query": map[string][]string{
			"client_id":             {registered.Client.ID},
			"redirect_uri":          {edgeRedirect},
			"response_type":         {"code"},
			"scope":                 {"openid"},
			"state":                 {"csrf"},
			"code_challenge":        {edgeChallenge()},
			"code_challenge_method": {"S256"},
		},
	}

	valid := runRequests(t, processor, standardsFrame(t, "valid", base))[0]
	result := standardsResult(t, valid)
	if result.Status != 200 || result.Action == nil || result.Action.Kind != "interaction" {
		t.Fatalf("valid authorization dispatch = %#v", result)
	}
	if result.Action.InteractionID == "" || result.Action.InteractionSecret == "" {
		t.Fatalf("interaction action omits its handle: %#v", result.Action)
	}
	if len(result.Body) != 0 {
		t.Fatalf("interaction action also returned an HTTP body: %s", result.Body)
	}

	duplicate := cloneStandardsRequest(t, base)
	duplicate["query"].(map[string][]string)["client_id"] = []string{registered.Client.ID, registered.Client.ID}
	rejected := standardsResult(t, runRequests(t, processor, standardsFrame(t, "duplicate", duplicate))[0])
	if rejected.Status != 400 || string(rejected.Body) != `{"error":"invalid_request"}` {
		t.Fatalf("duplicate parameter dispatch = %#v", rejected)
	}
	assertNoStore(t, rejected)

	untrusted := cloneStandardsRequest(t, base)
	untrusted["query"].(map[string][]string)["redirect_uri"] = []string{"https://evil.example/callback"}
	rejected = standardsResult(t, runRequests(t, processor, standardsFrame(t, "redirect", untrusted))[0])
	if rejected.Status != 400 || strings.Contains(string(rejected.Body), "evil.example") {
		t.Fatalf("untrusted redirect dispatch = %#v", rejected)
	}
	if _, present := rejected.Headers["location"]; present {
		t.Fatalf("an untrusted redirect produced Location: %#v", rejected.Headers)
	}
	assertNoStore(t, rejected)
}

func TestStandardsDispatchExecutesProtectedEndpointBoundaries(t *testing.T) {
	t.Parallel()

	processor, registered := standardsProcessor(t)
	authorization := testBasicAuthorization(registered.Client.ID, registered.Secret)
	tests := []struct {
		name      string
		request   map[string]any
		status    int
		body      string
		emptyBody bool
	}{
		{
			name: "token",
			request: map[string]any{
				"contract_version": "1",
				"endpoint":         "oidc.token",
				"method":           "POST",
				"authorization":    authorization,
				"form": map[string][]string{
					"grant_type": {"unsupported"},
				},
			},
			status: 400,
			body:   `{"error":"invalid_request"}`,
		},
		{
			name: "introspection",
			request: map[string]any{
				"contract_version": "1",
				"endpoint":         "oidc.introspection",
				"method":           "POST",
				"authorization":    authorization,
				"form": map[string][]string{
					"token": {"not-a-token"},
				},
			},
			status: 200,
			body:   `{"active":false}`,
		},
		{
			name: "revocation",
			request: map[string]any{
				"contract_version": "1",
				"endpoint":         "oidc.revocation",
				"method":           "POST",
				"authorization":    authorization,
				"form": map[string][]string{
					"token": {"not-a-token"},
				},
			},
			status:    200,
			emptyBody: true,
		},
		{
			name: "logout",
			request: map[string]any{
				"contract_version": "1",
				"endpoint":         "oidc.logout",
				"method":           "GET",
				"query": map[string][]string{
					"id_token_hint": {"not-an-id-token"},
				},
			},
			status: 400,
			body:   `{"error":"invalid_request"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := standardsResult(t, runRequests(
				t,
				processor,
				standardsFrame(t, test.name, test.request),
			)[0])
			if result.Status != test.status {
				t.Fatalf("status = %d, want %d: %#v", result.Status, test.status, result)
			}
			if test.emptyBody {
				if len(result.Body) != 0 {
					t.Fatalf("body = %s, want empty", result.Body)
				}
			} else if string(result.Body) != test.body {
				t.Fatalf("body = %s, want %s", result.Body, test.body)
			}
			assertNoStore(t, result)
		})
	}
}

func TestStandardsDispatchEnforcesMethodsAndClientAuthenticationShape(t *testing.T) {
	t.Parallel()

	processor, registered := standardsProcessor(t)
	wrongMethod := map[string]any{
		"contract_version": "1",
		"endpoint":         "oidc.token",
		"method":           "GET",
	}
	result := standardsResult(t, runRequests(t, processor, standardsFrame(t, "method", wrongMethod))[0])
	if result.Status != 405 || result.Headers["allow"] != "POST" {
		t.Fatalf("wrong method dispatch = %#v", result)
	}

	dualAuthentication := map[string]any{
		"contract_version": "1",
		"endpoint":         "oidc.token",
		"method":           "POST",
		"authorization":    testBasicAuthorization(registered.Client.ID, registered.Secret),
		"form": map[string][]string{
			"grant_type":    {"authorization_code"},
			"code":          {"not-a-code"},
			"redirect_uri":  {edgeRedirect},
			"client_id":     {registered.Client.ID},
			"client_secret": {registered.Secret},
			"code_verifier": {edgeVerifier},
		},
	}
	result = standardsResult(t, runRequests(t, processor, standardsFrame(t, "dual", dualAuthentication))[0])
	if result.Status != 400 || string(result.Body) != `{"error":"invalid_request"}` {
		t.Fatalf("dual client authentication dispatch = %#v", result)
	}
	if strings.Contains(string(result.Body), registered.Secret) {
		t.Fatal("client secret reached the standards response")
	}

	malformedAuthentication := map[string]any{
		"contract_version": "1",
		"endpoint":         "oidc.token",
		"method":           "POST",
		"authorization":    "Basic definitely-not-base64",
		"form": map[string][]string{
			"grant_type": {"authorization_code"},
		},
	}
	result = standardsResult(t, runRequests(t, processor,
		standardsFrame(t, "malformed-basic", malformedAuthentication))[0])
	if result.Status != 401 ||
		string(result.Body) != `{"error":"invalid_client"}` ||
		result.Headers["www-authenticate"] == "" {
		t.Fatalf("malformed client authentication dispatch = %#v", result)
	}

	unknown := map[string]any{
		"contract_version": "1",
		"endpoint":         "oidc.userinfo",
		"method":           "GET",
	}
	response := runRequests(t, processor, standardsFrame(t, "unknown", unknown))[0]
	if response.OK || response.Error == nil || response.Error.Code != ErrorInvalidRequest {
		t.Fatalf("unknown endpoint response = %#v", response)
	}
}

func TestStandardsDispatchPublishesDiscoveryAndOnlyPublicSigningKeys(t *testing.T) {
	t.Parallel()

	processor, _ := standardsProcessor(t)
	discovery := map[string]any{
		"contract_version": "1",
		"endpoint":         "oidc.discovery",
		"method":           "GET",
		"endpoints": map[string]string{
			"authorization_endpoint": "/authorize",
			"token_endpoint":         "/token",
			"jwks_uri":               "/.well-known/jwks.json",
			"introspection_endpoint": "/introspect",
			"revocation_endpoint":    "/revoke",
			"end_session_endpoint":   "/logout",
		},
	}
	result := standardsResult(t, runRequests(t, processor, standardsFrame(t, "discovery", discovery))[0])
	if result.Status != 200 ||
		!strings.Contains(string(result.Body), `"issuer":"https://id.example"`) ||
		!strings.Contains(string(result.Body), `"token_endpoint":"https://id.example/token"`) {
		t.Fatalf("discovery dispatch = %#v", result)
	}

	jwks := map[string]any{
		"contract_version": "1",
		"endpoint":         "oidc.jwks",
		"method":           "GET",
	}
	result = standardsResult(t, runRequests(t, processor, standardsFrame(t, "jwks", jwks))[0])
	body := string(result.Body)
	if result.Status != 200 || !strings.Contains(body, `"alg":"ES256"`) ||
		strings.Contains(body, `"d":`) || strings.Contains(body, `"p":`) ||
		strings.Contains(body, `"q":`) {
		t.Fatalf("JWKS dispatch = %#v", result)
	}
}

func TestStandardsDispatchRejectsControlCharactersAtTheContractBoundary(t *testing.T) {
	t.Parallel()

	processor, _ := standardsProcessor(t)
	request := map[string]any{
		"contract_version": "1",
		"endpoint":         "oidc.token",
		"method":           "POST",
		"authorization":    "Basic safe\r\nX-Injected: yes",
	}
	response := runRequests(t, processor, standardsFrame(t, "controls", request))[0]
	if response.OK || response.Error == nil || response.Error.Code != ErrorInvalidRequest {
		t.Fatalf("control-character response = %#v", response)
	}
}

func TestStandardsDispatchBoundsTheSerializedEnvelope(t *testing.T) {
	t.Parallel()

	processor, _ := standardsProcessor(t)
	values := make([]string, 7)
	for index := range values {
		values[index] = strings.Repeat(`"`, maxStandardsValueBytes)
	}
	request := map[string]any{
		"contract_version": "1",
		"endpoint":         "oidc.token",
		"method":           "POST",
		"form": map[string][]string{
			"escaped": values,
		},
	}
	response := runRequests(t, processor, standardsFrame(t, "serialized-limit", request))[0]
	if response.OK || response.Error == nil || response.Error.Code != ErrorInvalidRequest {
		t.Fatalf("oversized serialized envelope response = %#v", response)
	}
}

func TestBasicClientAuthenticationDecodesFormEncodedCredentials(t *testing.T) {
	t.Parallel()

	clientID := "client:with space"
	clientSecret := "secret+with/slash"
	encoded := base64.StdEncoding.EncodeToString([]byte(
		url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret),
	))
	gotID, gotSecret, ok := parseBasicAuthorization("Basic " + encoded)
	if !ok || gotID != clientID || gotSecret != clientSecret {
		t.Fatalf("parseBasicAuthorization() = %q, %q, %v", gotID, gotSecret, ok)
	}
}

type decodedStandardsResult struct {
	ContractVersion string            `json:"contract_version"`
	Status          int               `json:"status"`
	Headers         map[string]string `json:"headers"`
	Body            json.RawMessage   `json:"body"`
	Action          *struct {
		Kind              string `json:"kind"`
		InteractionID     string `json:"interaction_id"`
		InteractionSecret string `json:"interaction_secret"`
	} `json:"action"`
}

func standardsProcessor(t *testing.T) (*Processor, identity.ClientRegistration) {
	t.Helper()

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

	tenant, err := service.Bootstrap(context.Background(), "standards", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	registered, err := service.ClientRegister(
		context.Background(),
		tenant.Tenant.ID,
		"standards-client",
		"confidential",
		[]string{edgeRedirect},
		nil,
		oidcdomain.AudienceFirstParty,
		[]string{"https://app.example/signed-out"},
		"test",
	)
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	return New(system.New(buildinfo.New("", "", "")), service), registered
}

func standardsFrame(t *testing.T, requestID string, parameters any) string {
	t.Helper()

	frame, err := json.Marshal(map[string]any{
		"protocol_version": "1",
		"request_id":       requestID,
		"operation":        "standards.dispatch",
		"parameters":       parameters,
	})
	if err != nil {
		t.Fatalf("marshal standards frame: %v", err)
	}
	return string(frame)
}

func standardsResult(t *testing.T, response Response) decodedStandardsResult {
	t.Helper()

	if !response.OK {
		t.Fatalf("standards dispatch failed at the machine boundary: %#v", response)
	}
	var result decodedStandardsResult
	if err := json.Unmarshal(mustMarshal(t, response.Result), &result); err != nil {
		t.Fatalf("decode standards response: %v", err)
	}
	return result
}

func assertNoStore(t *testing.T, response decodedStandardsResult) {
	t.Helper()

	if response.Headers["cache-control"] != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Headers["cache-control"])
	}
	if response.Headers["pragma"] != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", response.Headers["pragma"])
	}
}

func cloneStandardsRequest(t *testing.T, source map[string]any) map[string]any {
	t.Helper()

	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("marshal standards request: %v", err)
	}
	var clone map[string]any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatalf("clone standards request: %v", err)
	}
	query := make(map[string][]string)
	for key, values := range clone["query"].(map[string]any) {
		for _, value := range values.([]any) {
			query[key] = append(query[key], value.(string))
		}
	}
	clone["query"] = query
	return clone
}

func testBasicAuthorization(clientID, clientSecret string) string {
	credentials := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	return "Basic " + credentials
}
