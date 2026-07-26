package machine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	scimdomain "github.com/d31ma/sesame/internal/domain/scim"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

// scimEdge builds a processor with one tenant and one provisioning client,
// registered through the machine protocol as a host would.
func scimEdge(t *testing.T) (*Processor, *identity.Service, string, string) {
	t.Helper()

	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	processor := New(system.New(buildinfo.New("", "", "")), service)

	tenant, err := service.Bootstrap(context.Background(), "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	registered := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-1","operation":"scim.client_register",`+
			`"parameters":{"tenant_id":"`+tenant.Tenant.ID+`","name":"Okta production"}}`)
	if !registered[0].OK {
		t.Fatalf("client_register failed: %+v", registered[0].Error)
	}
	var payload struct {
		Token string `json:"token"`
	}
	decodeResult(t, registered[0].Result, &payload)
	if payload.Token == "" {
		t.Fatal("client_register returned no token")
	}
	return processor, service, tenant.Tenant.ID, payload.Token
}

func scimBody(t *testing.T, overrides map[string]any) string {
	t.Helper()

	document := map[string]any{
		"schemas":  []string{scimdomain.SchemaUser},
		"userName": "person@example.com",
	}
	for name, value := range overrides {
		document[name] = value
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

// TestSCIMEdgeProvisionsAndDeprovisions drives the lifecycle a directory
// drives.
func TestSCIMEdgeProvisionsAndDeprovisions(t *testing.T) {
	t.Parallel()

	processor, _, _, token := scimEdge(t)

	created := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-2","operation":"scim.user_create",`+
			`"parameters":{"token":"`+token+`","body":`+jsonString(t, scimBody(t, nil))+`}}`)
	if !created[0].OK {
		t.Fatalf("user_create failed: %+v", created[0].Error)
	}
	var user struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}
	decodeResult(t, created[0].Result, &user)
	if user.ID == "" || !user.Active {
		t.Fatalf("created %#v", user)
	}

	read := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-3","operation":"scim.user_get",`+
			`"parameters":{"token":"`+token+`","resource_id":"`+user.ID+`"}}`)
	if !read[0].OK {
		t.Fatalf("user_get failed: %+v", read[0].Error)
	}

	listed := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-4","operation":"scim.user_list",`+
			`"parameters":{"token":"`+token+`","filter":"userName eq \"person@example.com\""}}`)
	if !listed[0].OK {
		t.Fatalf("user_list failed: %+v", listed[0].Error)
	}
	var list struct {
		TotalResults int `json:"totalResults"`
	}
	decodeResult(t, listed[0].Result, &list)
	if list.TotalResults != 1 {
		t.Fatalf("list returned %d users", list.TotalResults)
	}

	gone := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-5","operation":"scim.user_deprovision",`+
			`"parameters":{"token":"`+token+`","resource_id":"`+user.ID+`"}}`)
	if !gone[0].OK {
		t.Fatalf("user_deprovision failed: %+v", gone[0].Error)
	}
	// Deprovisioning suspends: the user is still readable, and inactive.
	after := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-6","operation":"scim.user_get",`+
			`"parameters":{"token":"`+token+`","resource_id":"`+user.ID+`"}}`)
	if !after[0].OK {
		t.Fatalf("a deprovisioned user is unreadable: %+v", after[0].Error)
	}
	decodeResult(t, after[0].Result, &user)
	if user.Active {
		t.Fatal("a deprovisioned user is still active")
	}
}

// TestSCIMEdgeRefusesABadToken: every resource operation authenticates, so
// none of them can be reached without a credential.
func TestSCIMEdgeRefusesABadToken(t *testing.T) {
	t.Parallel()

	processor, _, _, _ := scimEdge(t)

	for _, operation := range []string{
		"scim.user_create", "scim.user_get", "scim.user_list",
		"scim.user_patch", "scim.user_deprovision",
	} {
		t.Run(operation, func(t *testing.T) {
			responses := runRequests(t, processor,
				`{"protocol_version":"1","request_id":"scim-7","operation":"`+operation+
					`","parameters":{"token":"a-forged-token","resource_id":"prn_x","body":"{}"}}`)
			if responses[0].OK {
				t.Fatalf("%s succeeded with a forged token", operation)
			}
			if responses[0].Error.Code != ErrorProvisioningDenied {
				t.Fatalf("%s code = %q, want %q",
					operation, responses[0].Error.Code, ErrorProvisioningDenied)
			}
		})
	}
}

// TestSCIMEdgeReportsAConflictDistinctly: a directory reconciles against
// SCIM's 409. Collapsing it into a generic failure would leave a provider
// retrying a create forever.
func TestSCIMEdgeReportsAConflictDistinctly(t *testing.T) {
	t.Parallel()

	processor, _, _, token := scimEdge(t)
	create := `{"protocol_version":"1","request_id":"scim-8","operation":"scim.user_create",` +
		`"parameters":{"token":"` + token + `","body":` + jsonString(t, scimBody(t, nil)) + `}}`

	if first := runRequests(t, processor, create); !first[0].OK {
		t.Fatalf("the first create failed: %+v", first[0].Error)
	}
	second := runRequests(t, processor, create)
	if second[0].OK {
		t.Fatal("a duplicate userName was created twice")
	}
	if second[0].Error.Code != ErrorSCIMConflict {
		t.Fatalf("code = %q, want %q", second[0].Error.Code, ErrorSCIMConflict)
	}
}

// TestSCIMEdgeNamesWhatItWillNotDo: an unsupported filter or PATCH is
// well-formed but outside the subset, and the reason has to say which so an
// operator can fix their configuration.
func TestSCIMEdgeNamesWhatItWillNotDo(t *testing.T) {
	t.Parallel()

	processor, _, _, token := scimEdge(t)

	filtered := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-9","operation":"scim.user_list",`+
			`"parameters":{"token":"`+token+`","filter":"userName eq \"a\" and active eq true"}}`)
	if filtered[0].OK {
		t.Fatal("a compound filter was evaluated")
	}
	if filtered[0].Error.Code != ErrorSCIMUnsupported {
		t.Fatalf("code = %q, want %q", filtered[0].Error.Code, ErrorSCIMUnsupported)
	}
	if !strings.Contains(filtered[0].Error.Message, "compound") {
		t.Fatalf("the refusal does not name the problem: %q", filtered[0].Error.Message)
	}

	created := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-10","operation":"scim.user_create",`+
			`"parameters":{"token":"`+token+`","body":`+jsonString(t, scimBody(t, nil))+`}}`)
	var user struct {
		ID string `json:"id"`
	}
	decodeResult(t, created[0].Result, &user)

	patch := jsonString(t, `{"schemas":["`+scimdomain.SchemaPatch+
		`"],"Operations":[{"op":"remove","path":"active"}]}`)
	patched := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-11","operation":"scim.user_patch",`+
			`"parameters":{"token":"`+token+`","resource_id":"`+user.ID+`","body":`+patch+`}}`)
	if patched[0].OK {
		t.Fatal("an unsupported PATCH operation was applied")
	}
	if patched[0].Error.Code != ErrorSCIMUnsupported {
		t.Fatalf("code = %q, want %q", patched[0].Error.Code, ErrorSCIMUnsupported)
	}
}

// TestSCIMEdgeDisableStopsProvisioning covers the operator's remedy for a
// leaked provisioning token.
func TestSCIMEdgeDisableStopsProvisioning(t *testing.T) {
	t.Parallel()

	processor, service, tenantID, token := scimEdge(t)

	client, err := service.ProvisioningAuthenticate(token)
	if err != nil {
		t.Fatalf("ProvisioningAuthenticate() error = %v", err)
	}
	disabled := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-12","operation":"scim.client_disable",`+
			`"parameters":{"tenant_id":"`+tenantID+`","scim_client_id":"`+client.ID+
			`","reason":"token leaked"}}`)
	if !disabled[0].OK {
		t.Fatalf("client_disable failed: %+v", disabled[0].Error)
	}

	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-13","operation":"scim.user_create",`+
			`"parameters":{"token":"`+token+`","body":`+jsonString(t, scimBody(t, nil))+`}}`)
	if responses[0].OK {
		t.Fatal("a disabled client provisioned")
	}
	if responses[0].Error.Code != ErrorProvisioningDenied {
		t.Fatalf("code = %q, want %q", responses[0].Error.Code, ErrorProvisioningDenied)
	}
}

// TestSCIMOperationsRequireStorage covers the fail-closed path.
func TestSCIMOperationsRequireStorage(t *testing.T) {
	t.Parallel()

	processor := New(system.New(buildinfo.New("", "", "")), nil)
	for _, operation := range []string{
		"scim.client_register", "scim.client_disable", "scim.user_create",
		"scim.user_get", "scim.user_list", "scim.user_patch", "scim.user_deprovision",
	} {
		responses := runRequests(t, processor,
			`{"protocol_version":"1","request_id":"scim-14","operation":"`+operation+
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

// TestSCIMEdgeNeverReturnsTheTokenTwice: it is stored as a digest, so there is
// nothing to return later even to an administrator.
func TestSCIMEdgeNeverReturnsTheTokenTwice(t *testing.T) {
	t.Parallel()

	processor, service, tenantID, token := scimEdge(t)

	client, err := service.ProvisioningAuthenticate(token)
	if err != nil {
		t.Fatalf("ProvisioningAuthenticate() error = %v", err)
	}
	// Registering a second client must mint a different token.
	again := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-15","operation":"scim.client_register",`+
			`"parameters":{"tenant_id":"`+tenantID+`","name":"Entra"}}`)
	var payload struct {
		Token  string `json:"token"`
		Client struct {
			ID string `json:"scim_client_id"`
		} `json:"client"`
	}
	decodeResult(t, again[0].Result, &payload)
	if payload.Token == token {
		t.Fatal("two provisioning clients were minted the same token")
	}
	if payload.Client.ID == client.ID {
		t.Fatal("two provisioning clients share an identifier")
	}
}

// TestSCIMEdgeRotatesATokenWithNoOverlap: rotation is the remedy for a leaked
// token that does not also halt the directory, and an overlap window is
// exactly what the leak-holder would use.
func TestSCIMEdgeRotatesATokenWithNoOverlap(t *testing.T) {
	t.Parallel()

	processor, service, tenantID, token := scimEdge(t)

	client, err := service.ProvisioningAuthenticate(token)
	if err != nil {
		t.Fatalf("ProvisioningAuthenticate() error = %v", err)
	}
	rotated := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-16","operation":"scim.client_rotate_token",`+
			`"parameters":{"tenant_id":"`+tenantID+`","scim_client_id":"`+client.ID+`"}}`)
	if !rotated[0].OK {
		t.Fatalf("client_rotate_token failed: %+v", rotated[0].Error)
	}
	var payload struct {
		Token string `json:"token"`
	}
	decodeResult(t, rotated[0].Result, &payload)
	if payload.Token == "" || payload.Token == token {
		t.Fatalf("rotation returned %q", payload.Token)
	}

	// The old token is dead the moment the new one exists.
	stale := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-17","operation":"scim.user_create",`+
			`"parameters":{"token":"`+token+`","body":`+jsonString(t, scimBody(t, nil))+`}}`)
	if stale[0].OK {
		t.Fatal("the rotated-out token still provisions")
	}
	if stale[0].Error.Code != ErrorProvisioningDenied {
		t.Fatalf("code = %q, want %q", stale[0].Error.Code, ErrorProvisioningDenied)
	}

	// The replacement works, and provisions as the same client.
	fresh := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-18","operation":"scim.user_create",`+
			`"parameters":{"token":"`+payload.Token+`","body":`+
			jsonString(t, scimBody(t, nil))+`}}`)
	if !fresh[0].OK {
		t.Fatalf("the replacement token does not provision: %+v", fresh[0].Error)
	}

	// An unknown client cannot be rotated, and the refusal does not confirm
	// which client identifiers exist.
	unknown := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"scim-19","operation":"scim.client_rotate_token",`+
			`"parameters":{"tenant_id":"`+tenantID+
			`","scim_client_id":"scm_00000000000000000000000000000000"}}`)
	if unknown[0].OK {
		t.Fatal("an unknown provisioning client was rotated")
	}
	if unknown[0].Error.Code != ErrorProvisioningClient {
		t.Fatalf("code = %q, want %q", unknown[0].Error.Code, ErrorProvisioningClient)
	}
}
