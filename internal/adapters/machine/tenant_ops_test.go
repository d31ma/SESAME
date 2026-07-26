package machine

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	"github.com/d31ma/sesame/internal/domain/audit"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

type memoryLedger struct {
	events []audit.Event
}

func (l *memoryLedger) Append(
	_ context.Context,
	eventType string,
	tenantID string,
	actor string,
	payload any,
) (audit.Event, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return audit.Event{}, err
	}
	previousHash := ""
	if len(l.events) > 0 {
		previousHash = l.events[len(l.events)-1].Hash
	}
	event := audit.Event{
		Kind:          audit.EventKind,
		SchemaVersion: audit.SchemaVersion,
		Sequence:      int64(len(l.events)) + 1,
		Type:          eventType,
		TenantID:      tenantID,
		Actor:         actor,
		OccurredAt:    "2026-07-24T00:00:00Z",
		Payload:       encoded,
		PreviousHash:  previousHash,
	}
	event.Hash = event.Digest()
	l.events = append(l.events, event)
	return event, nil
}

func runRequests(t *testing.T, processor *Processor, requests ...string) []Response {
	t.Helper()

	var output bytes.Buffer
	input := strings.Join(requests, "\n") + "\n"
	if err := processor.Run(context.Background(), strings.NewReader(input), &output); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	responses := make([]Response, 0, len(lines))
	for _, line := range lines {
		var response Response
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatalf("response is not JSON: %q: %v", line, err)
		}
		responses = append(responses, response)
	}
	if len(responses) != len(requests) {
		t.Fatalf("got %d responses for %d requests", len(responses), len(requests))
	}
	return responses
}

func TestSystemMetricsCountsRequestsAndErrors(t *testing.T) {
	t.Parallel()

	processor := New(system.New(buildinfo.New("", "", "")), nil)
	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"ping-1","operation":"system.ping","parameters":{}}`,
		`{"protocol_version":"1","request_id":"ping-2","operation":"system.ping","parameters":{}}`,
		`{"protocol_version":"1","request_id":"missing-1","operation":"identity.create","parameters":{}}`,
		`{"protocol_version":"1","request_id":"boot-1","operation":"tenant.bootstrap","parameters":{"name":"acme"}}`,
		`{"protocol_version":"1","request_id":"metrics-1","operation":"system.metrics","parameters":{}}`,
	)

	last := responses[len(responses)-1]
	if !last.OK {
		t.Fatalf("metrics response = %#v", last)
	}
	encoded, err := json.Marshal(last.Result)
	if err != nil {
		t.Fatalf("marshal metrics: %v", err)
	}
	var report MetricsReport
	if err := json.Unmarshal(encoded, &report); err != nil {
		t.Fatalf("decode metrics: %v", err)
	}
	if report.StorageConfigured {
		t.Fatal("metrics report storage as configured without a tenant service")
	}
	// The report excludes the in-flight system.metrics request itself.
	if report.RequestsTotal["system.ping"] != 2 ||
		report.RequestsTotal["identity.create"] != 1 ||
		report.RequestsTotal["tenant.bootstrap"] != 1 {
		t.Fatalf("requests_total = %#v", report.RequestsTotal)
	}
	if report.ErrorsTotal[ErrorOperationNotFound] != 1 ||
		report.ErrorsTotal[ErrorStorageNotConfigured] != 1 {
		t.Fatalf("errors_total = %#v", report.ErrorsTotal)
	}
	if report.Goroutines < 1 || report.UptimeSeconds < 0 {
		t.Fatalf("runtime metrics = %#v", report)
	}
}

func TestTenantOperationsFailClosedWithoutStorage(t *testing.T) {
	t.Parallel()

	processor := New(system.New(buildinfo.New("", "", "")), nil)
	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"boot-1","operation":"tenant.bootstrap","parameters":{"name":"acme"}}`,
		`{"protocol_version":"1","request_id":"get-1","operation":"tenant.get","parameters":{"name":"acme"}}`,
	)
	for _, response := range responses {
		if response.OK || response.Error == nil || response.Error.Code != ErrorStorageNotConfigured {
			t.Fatalf("response = %#v, want %s", response, ErrorStorageNotConfigured)
		}
	}
}

func TestPrincipalLifecycleThroughMachineEdge(t *testing.T) {
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
	encoded, _ := json.Marshal(bootstrap.Result)
	if err := json.Unmarshal(encoded, &bootResult); err != nil {
		t.Fatalf("decode bootstrap: %v", err)
	}
	tenantID := bootResult.Tenant.ID

	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"create-1","operation":"principal.create","parameters":{"tenant_id":"`+tenantID+`","kind":"human","identifier_namespace":"email","identifier_value":"Alice@Example.com"}}`,
		`{"protocol_version":"1","request_id":"create-2","operation":"principal.create","parameters":{"tenant_id":"`+tenantID+`","kind":"human","identifier_namespace":"email","identifier_value":"alice@example.com"}}`,
		`{"protocol_version":"1","request_id":"get-1","operation":"principal.get","parameters":{"tenant_id":"`+tenantID+`","identifier_namespace":"email","identifier_value":"alice@example.com"}}`,
		`{"protocol_version":"1","request_id":"get-2","operation":"principal.get","parameters":{"principal_id":"prn_00000000000000000000000000000000"}}`,
		`{"protocol_version":"1","request_id":"bad-1","operation":"principal.get","parameters":{}}`,
		`{"protocol_version":"1","request_id":"bad-2","operation":"principal.create","parameters":{"tenant_id":"`+tenantID+`","kind":"robot","identifier_namespace":"email","identifier_value":"bob@example.com"}}`,
	)

	if !responses[0].OK {
		t.Fatalf("principal.create response = %#v", responses[0])
	}
	var created struct {
		PrincipalID string `json:"principal_id"`
		Status      string `json:"status"`
		Identifier  struct {
			Value string `json:"value"`
		} `json:"identifier"`
	}
	encoded, _ = json.Marshal(responses[0].Result)
	if err := json.Unmarshal(encoded, &created); err != nil {
		t.Fatalf("decode created principal: %v", err)
	}
	if created.Status != "active" || created.Identifier.Value != "alice@example.com" {
		t.Fatalf("created principal = %#v", created)
	}
	for index, wantCode := range map[int]string{
		1: ErrorIdentifierConflict,
		3: ErrorPrincipalNotFound,
		4: ErrorInvalidRequest,
		5: ErrorInvalidRequest,
	} {
		response := responses[index]
		if response.OK || response.Error == nil || response.Error.Code != wantCode {
			t.Fatalf("response %d = %#v, want error code %s", index, response, wantCode)
		}
	}
	if !responses[2].OK || !strings.Contains(string(mustMarshal(t, responses[2].Result)), created.PrincipalID) {
		t.Fatalf("principal.get by identifier = %#v", responses[2])
	}

	suspend := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"suspend-1","operation":"principal.suspend","parameters":{"principal_id":"`+created.PrincipalID+`"}}`,
		`{"protocol_version":"1","request_id":"suspend-2","operation":"principal.suspend","parameters":{"principal_id":"`+created.PrincipalID+`"}}`,
	)
	for index, response := range suspend {
		if !response.OK || !strings.Contains(string(mustMarshal(t, response.Result)), `"suspended"`) {
			t.Fatalf("suspend response %d = %#v", index, response)
		}
	}
}

func TestAuthorizationThroughMachineEdge(t *testing.T) {
	t.Parallel()

	tenantService, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	processor := New(system.New(buildinfo.New("", "", "")), tenantService)

	decodeInto := func(response Response, target any) {
		if err := json.Unmarshal(mustMarshal(t, response.Result), target); err != nil {
			t.Fatalf("decode result: %v", err)
		}
	}

	setup := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"boot","operation":"tenant.bootstrap","parameters":{"name":"acme"}}`,
	)
	var boot identity.BootstrapResult
	decodeInto(setup[0], &boot)
	tenantID := boot.Tenant.ID

	setup = runRequests(t, processor,
		`{"protocol_version":"1","request_id":"prn","operation":"principal.create","parameters":{"tenant_id":"`+tenantID+`","kind":"human","identifier_namespace":"email","identifier_value":"alice@example.com"}}`,
		`{"protocol_version":"1","request_id":"role","operation":"role.create","parameters":{"tenant_id":"`+tenantID+`","name":"reader","permissions":[{"action":"doc:read","resource":"*"}]}}`,
	)
	var principal struct {
		ID string `json:"principal_id"`
	}
	decodeInto(setup[0], &principal)
	var role struct {
		ID string `json:"role_id"`
	}
	if !setup[1].OK {
		t.Fatalf("role.create = %#v", setup[1])
	}
	decodeInto(setup[1], &role)

	flow := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"deny-1","operation":"authorize.decide","parameters":{"tenant_id":"`+tenantID+`","principal_id":"`+principal.ID+`","action":"doc:read","resource":"file:a"}}`,
		`{"protocol_version":"1","request_id":"grant","operation":"grant.create","parameters":{"tenant_id":"`+tenantID+`","principal_id":"`+principal.ID+`","role_id":"`+role.ID+`"}}`,
		`{"protocol_version":"1","request_id":"allow-1","operation":"authorize.decide","parameters":{"tenant_id":"`+tenantID+`","principal_id":"`+principal.ID+`","action":"doc:read","resource":"file:a"}}`,
		`{"protocol_version":"1","request_id":"batch","operation":"authorize.decide_batch","parameters":{"requests":[{"tenant_id":"`+tenantID+`","principal_id":"`+principal.ID+`","action":"doc:read","resource":"file:a"},{"tenant_id":"`+tenantID+`","principal_id":"`+principal.ID+`","action":"doc:write","resource":"file:a"}]}}`,
		`{"protocol_version":"1","request_id":"stale","operation":"authorize.decide","parameters":{"tenant_id":"`+tenantID+`","principal_id":"`+principal.ID+`","action":"doc:read","resource":"file:a","policy_version":1}}`,
		`{"protocol_version":"1","request_id":"dup-role","operation":"role.create","parameters":{"tenant_id":"`+tenantID+`","name":"reader","permissions":[{"action":"*","resource":"*"}]}}`,
	)

	var denied identity.Decision
	decodeInto(flow[0], &denied)
	if denied.Decision != "deny" || denied.ReasonCode != identity.ReasonDenyNoGrant {
		t.Fatalf("pre-grant decision = %#v", denied)
	}
	var grant struct {
		ID string `json:"grant_id"`
	}
	if !flow[1].OK {
		t.Fatalf("grant.create = %#v", flow[1])
	}
	decodeInto(flow[1], &grant)
	var allowed identity.Decision
	decodeInto(flow[2], &allowed)
	if allowed.Decision != "allow" || allowed.ReasonCode != identity.ReasonAllowRoleGrant {
		t.Fatalf("post-grant decision = %#v", allowed)
	}
	var batch struct {
		Decisions []identity.Decision `json:"decisions"`
	}
	decodeInto(flow[3], &batch)
	if len(batch.Decisions) != 2 || batch.Decisions[0].Decision != "allow" || batch.Decisions[1].Decision != "deny" {
		t.Fatalf("batch = %#v", batch)
	}
	if flow[4].OK || flow[4].Error.Code != ErrorStalePolicyVersion {
		t.Fatalf("stale pin = %#v", flow[4])
	}
	if flow[5].OK || flow[5].Error.Code != ErrorRoleExists {
		t.Fatalf("duplicate role = %#v", flow[5])
	}

	revoke := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"revoke","operation":"grant.revoke","parameters":{"grant_id":"`+grant.ID+`"}}`,
		`{"protocol_version":"1","request_id":"deny-2","operation":"authorize.decide","parameters":{"tenant_id":"`+tenantID+`","principal_id":"`+principal.ID+`","action":"doc:read","resource":"file:a"}}`,
		`{"protocol_version":"1","request_id":"revoke-2","operation":"grant.revoke","parameters":{"grant_id":"`+grant.ID+`"}}`,
	)
	if !revoke[0].OK {
		t.Fatalf("grant.revoke = %#v", revoke[0])
	}
	var afterRevoke identity.Decision
	decodeInto(revoke[1], &afterRevoke)
	if afterRevoke.Decision != "deny" || afterRevoke.ReasonCode != identity.ReasonDenyNoGrant {
		t.Fatalf("post-revoke decision = %#v", afterRevoke)
	}
	if revoke[2].OK || revoke[2].Error.Code != ErrorGrantNotFound {
		t.Fatalf("second revoke = %#v", revoke[2])
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

func TestTenantBootstrapAndGetThroughMachineEdge(t *testing.T) {
	t.Parallel()

	tenantService, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	processor := New(system.New(buildinfo.New("", "", "")), tenantService)

	responses := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"boot-1","operation":"tenant.bootstrap","parameters":{"name":"Acme"}}`,
		`{"protocol_version":"1","request_id":"boot-2","operation":"tenant.bootstrap","parameters":{"name":"acme"}}`,
		`{"protocol_version":"1","request_id":"get-1","operation":"tenant.get","parameters":{"name":"acme"}}`,
		`{"protocol_version":"1","request_id":"get-2","operation":"tenant.get","parameters":{"name":"missing"}}`,
		`{"protocol_version":"1","request_id":"bad-1","operation":"tenant.get","parameters":{"name":"acme","tenant_id":"tnt_x"}}`,
		`{"protocol_version":"1","request_id":"bad-2","operation":"tenant.get","parameters":{}}`,
		`{"protocol_version":"1","request_id":"bad-3","operation":"tenant.bootstrap","parameters":{"name":"acme","surprise":true}}`,
		`{"protocol_version":"1","request_id":"bad-4","operation":"tenant.bootstrap","parameters":{"name":"bad name!"}}`,
	)

	decodeResult := func(index int, target any) {
		encoded, err := json.Marshal(responses[index].Result)
		if err != nil {
			t.Fatalf("marshal result %d: %v", index, err)
		}
		if err := json.Unmarshal(encoded, target); err != nil {
			t.Fatalf("decode result %d: %v", index, err)
		}
	}

	var first identity.BootstrapResult
	if !responses[0].OK {
		t.Fatalf("bootstrap response = %#v", responses[0])
	}
	decodeResult(0, &first)
	if !first.Created || first.Tenant.Name != "acme" {
		t.Fatalf("bootstrap result = %#v", first)
	}

	var second identity.BootstrapResult
	decodeResult(1, &second)
	if second.Created || second.Tenant.ID != first.Tenant.ID {
		t.Fatalf("repeat bootstrap result = %#v", second)
	}

	if !responses[2].OK {
		t.Fatalf("get response = %#v", responses[2])
	}
	for index, wantCode := range map[int]string{
		3: ErrorTenantNotFound,
		4: ErrorInvalidRequest,
		5: ErrorInvalidRequest,
		6: ErrorInvalidRequest,
		7: ErrorInvalidRequest,
	} {
		response := responses[index]
		if response.OK || response.Error == nil || response.Error.Code != wantCode {
			t.Fatalf("response %d = %#v, want error code %s", index, response, wantCode)
		}
	}
}

func TestAuthenticationThroughMachineEdge(t *testing.T) {
	t.Parallel()

	tenantService, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	processor := New(system.New(buildinfo.New("", "", "")), tenantService)
	decodeInto := func(response Response, target any) {
		t.Helper()
		if err := json.Unmarshal(mustMarshal(t, response.Result), target); err != nil {
			t.Fatalf("decode result: %v", err)
		}
	}

	setup := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"boot","operation":"tenant.bootstrap","parameters":{"name":"acme"}}`,
	)
	var boot identity.BootstrapResult
	decodeInto(setup[0], &boot)
	tenantID := boot.Tenant.ID

	setup = runRequests(t, processor,
		`{"protocol_version":"1","request_id":"prn","operation":"principal.create","parameters":{"tenant_id":"`+tenantID+`","kind":"human","identifier_namespace":"email","identifier_value":"alice@example.com"}}`,
	)
	var principal struct {
		ID string `json:"principal_id"`
	}
	decodeInto(setup[0], &principal)

	const password = "correct horse battery staple"
	flow := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"pw","operation":"authenticator.set_password","parameters":{"principal_id":"`+principal.ID+`","password":"`+password+`"}}`,
		`{"protocol_version":"1","request_id":"begin","operation":"authn.begin","parameters":{"tenant_id":"`+tenantID+`","identifier_namespace":"email","identifier_value":"Alice@Example.com"}}`,
	)
	if !flow[0].OK || !flow[1].OK {
		t.Fatalf("setup flow = %#v %#v", flow[0], flow[1])
	}
	// The password must not be echoed back on any stream.
	if strings.Contains(string(mustMarshal(t, flow[0].Result)), password) {
		t.Fatal("set_password response echoes the password")
	}
	var begun identity.AuthenticationResult
	decodeInto(flow[1], &begun)

	wrong := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"bad","operation":"authn.verify_password","parameters":{"transaction_id":"`+begun.TransactionID+`","password":"wrong password value"}}`,
	)[0]
	var wrongResult identity.AuthenticationResult
	decodeInto(wrong, &wrongResult)
	if !wrong.OK || wrongResult.AttemptsLeft != 4 {
		t.Fatalf("wrong password = %#v", wrongResult)
	}

	good := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"good","operation":"authn.verify_password","parameters":{"transaction_id":"`+begun.TransactionID+`","password":"`+password+`"}}`,
		`{"protocol_version":"1","request_id":"done","operation":"authn.complete","parameters":{"transaction_id":"`+begun.TransactionID+`","lifetime_seconds":3600}}`,
	)
	var issued identity.IssuedSession
	decodeInto(good[1], &issued)
	if issued.Secret == "" || issued.SessionID == "" {
		t.Fatalf("complete = %#v", issued)
	}

	sessions := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"ver","operation":"session.verify","parameters":{"session_id":"`+issued.SessionID+`","session_secret":"`+issued.Secret+`"}}`,
		`{"protocol_version":"1","request_id":"bad-secret","operation":"session.verify","parameters":{"session_id":"`+issued.SessionID+`","session_secret":"nope"}}`,
		`{"protocol_version":"1","request_id":"rev","operation":"session.revoke","parameters":{"session_id":"`+issued.SessionID+`","reason":"test"}}`,
		`{"protocol_version":"1","request_id":"ver2","operation":"session.verify","parameters":{"session_id":"`+issued.SessionID+`","session_secret":"`+issued.Secret+`"}}`,
	)
	if !sessions[0].OK {
		t.Fatalf("session.verify = %#v", sessions[0])
	}
	// The stored digest must never cross the boundary.
	verified := string(mustMarshal(t, sessions[0].Result))
	if strings.Contains(verified, "secret_digest") || strings.Contains(verified, issued.Secret) {
		t.Fatalf("session.verify leaks secret material: %s", verified)
	}
	if sessions[1].OK || sessions[1].Error.Code != ErrorSessionNotFound {
		t.Fatalf("wrong secret = %#v", sessions[1])
	}
	if !sessions[2].OK {
		t.Fatalf("session.revoke = %#v", sessions[2])
	}
	if sessions[3].OK || sessions[3].Error.Code != ErrorSessionInactive {
		t.Fatalf("post-revoke verify = %#v", sessions[3])
	}

	// An unknown transaction and a closed one carry distinct stable codes.
	closed := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"unknown","operation":"authn.verify_password","parameters":{"transaction_id":"atx_00000000000000000000000000000000","password":"`+password+`"}}`,
		`{"protocol_version":"1","request_id":"reuse","operation":"authn.complete","parameters":{"transaction_id":"`+begun.TransactionID+`","lifetime_seconds":3600}}`,
	)
	if closed[0].OK || closed[0].Error.Code != ErrorTransactionNotFound {
		t.Fatalf("unknown transaction = %#v", closed[0])
	}
	if closed[1].OK || closed[1].Error.Code != ErrorTransactionClosed {
		t.Fatalf("completed transaction reuse = %#v", closed[1])
	}
}
