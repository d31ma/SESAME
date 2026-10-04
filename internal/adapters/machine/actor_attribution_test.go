package machine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

const (
	actorTestPassword = "correct horse battery staple"
	actorTestSetup    = "operator:test"
)

type actorFixture struct {
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	SessionID   string `json:"session_id"`
	secret      string
}

func (f actorFixture) recorded() string {
	return "principal:" + f.TenantID + "/" + f.PrincipalID + "/" + f.SessionID
}

type actorEdge struct {
	processor *Processor
	service   *identity.Service
	ledger    *memoryLedger
	alpha     actorFixture
	beta      actorFixture
}

func newActorEdge(t *testing.T) *actorEdge {
	t.Helper()

	ledger := &memoryLedger{}
	service, err := identity.New(ledger, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	edge := &actorEdge{
		processor: New(system.New(buildinfo.New("", "", "")), service),
		service:   service,
		ledger:    ledger,
	}
	edge.alpha = issueActorSession(t, service, "alpha", "alice@example.com")
	edge.beta = issueActorSession(t, service, "beta", "bob@example.com")
	return edge
}

func issueActorSession(t *testing.T, service *identity.Service, tenantName, email string) actorFixture {
	t.Helper()

	ctx := context.Background()
	boot, err := service.Bootstrap(ctx, tenantName, actorTestSetup)
	if err != nil {
		t.Fatalf("Bootstrap(%s) error = %v", tenantName, err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: email}
	principal, err := service.PrincipalCreate(ctx, boot.Tenant.ID, "human", identifier, actorTestSetup)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, actorTestPassword, actorTestSetup); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	begun, err := service.AuthenticationBegin(ctx, boot.Tenant.ID, identifier, actorTestSetup)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID, actorTestPassword, actorTestSetup); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	issued, err := service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, actorTestSetup)
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	return actorFixture{
		TenantID:    boot.Tenant.ID,
		PrincipalID: principal.ID,
		SessionID:   issued.SessionID,
		secret:      issued.Secret,
	}
}

func actorFrame(t *testing.T, requestID, operation string, parameters any, actor any) string {
	t.Helper()

	envelope := map[string]any{
		"protocol_version": ProtocolVersion,
		"request_id":       requestID,
		"operation":        operation,
		"parameters":       parameters,
	}
	if actor != nil {
		envelope["actor"] = actor
	}
	return string(mustMarshal(t, envelope))
}

func principalCreateParameters(tenantID, email string) map[string]any {
	return map[string]any{
		"tenant_id":            tenantID,
		"kind":                 "human",
		"identifier_namespace": "email",
		"identifier_value":     email,
	}
}

func (e *actorEdge) eventCount() int {
	return len(e.ledger.events)
}

func (e *actorEdge) lastEvent(t *testing.T) (string, string) {
	t.Helper()

	if len(e.ledger.events) == 0 {
		t.Fatal("the ledger holds no events")
	}
	last := e.ledger.events[len(e.ledger.events)-1]
	return last.Actor, last.TenantID
}

func TestAttributedRequestRecordsTheCallingPrincipal(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	response := runRequests(t, edge.processor,
		actorFrame(t, "attributed-create", "principal.create",
			principalCreateParameters(edge.alpha.TenantID, "carol@example.com"), edge.alpha),
	)[0]
	if !response.OK {
		t.Fatalf("attributed principal.create = %#v", response.Error)
	}

	actor, tenantID := edge.lastEvent(t)
	if actor != edge.alpha.recorded() {
		t.Fatalf("recorded actor = %q, want %q", actor, edge.alpha.recorded())
	}
	if tenantID != edge.alpha.TenantID {
		t.Fatalf("recorded tenant = %q, want %q", tenantID, edge.alpha.TenantID)
	}
}

func TestAbsentActorStillRecordsTheMachineOperator(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	before := edge.eventCount()
	responses := runRequests(t, edge.processor,
		actorFrame(t, "plain-create", "principal.create",
			principalCreateParameters(edge.alpha.TenantID, "dave@example.com"), nil),
		actorFrame(t, "plain-role", "role.create", map[string]any{
			"tenant_id":   edge.alpha.TenantID,
			"name":        "reader",
			"permissions": []map[string]string{{"action": "doc:read", "resource": "*"}},
		}, nil),
		actorFrame(t, "plain-revoke", "session.revoke", map[string]any{
			"session_id": edge.beta.SessionID,
		}, nil),
	)
	for _, response := range responses {
		if !response.OK {
			t.Fatalf("unattributed request %s = %#v", response.RequestID, response.Error)
		}
	}
	if edge.eventCount() != before+len(responses) {
		t.Fatalf("event count = %d, want %d", edge.eventCount(), before+len(responses))
	}
	for _, event := range edge.ledger.events[before:] {
		if event.Actor != "operator:machine" {
			t.Fatalf("unattributed %s recorded actor %q, want operator:machine", event.Type, event.Actor)
		}
	}
}

func TestVersionAdvertisesActorAttribution(t *testing.T) {
	t.Parallel()

	processor := New(system.New(buildinfo.New("", "", "")), nil)
	response := runRequests(t, processor,
		actorFrame(t, "version", "system.version", map[string]any{}, nil),
	)[0]
	var report VersionReport
	if err := json.Unmarshal(mustMarshal(t, response.Result), &report); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if strings.Join(report.RequestFields, ",") != "actor" {
		t.Fatalf("request_fields = %v, want [actor]", report.RequestFields)
	}
}

func assertRefusedWithoutWriting(t *testing.T, edge *actorEdge, before int, response Response, want string) {
	t.Helper()

	assertErrorCode(t, response, want)
	if edge.eventCount() != before {
		t.Fatalf("refused request %s appended %d events", response.RequestID, edge.eventCount()-before)
	}
}

func TestMalformedActorFailsClosed(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	valid := map[string]any{
		"tenant_id":    edge.alpha.TenantID,
		"principal_id": edge.alpha.PrincipalID,
		"session_id":   edge.alpha.SessionID,
	}
	with := func(key string, value any) map[string]any {
		changed := map[string]any{}
		for name, existing := range valid {
			changed[name] = existing
		}
		changed[key] = value
		return changed
	}
	without := func(key string) map[string]any {
		changed := with(key, nil)
		delete(changed, key)
		return changed
	}

	cases := map[string]any{
		"null":                   json.RawMessage(`null`),
		"string":                 edge.alpha.recorded(),
		"array":                  []string{edge.alpha.TenantID},
		"number":                 7,
		"empty object":           map[string]any{},
		"missing session":        without("session_id"),
		"malformed tenant":       with("tenant_id", "tnt_not-hex"),
		"principal as tenant":    with("tenant_id", edge.alpha.PrincipalID),
		"nested tenant":          with("tenant_id", map[string]string{"id": edge.alpha.TenantID}),
		"unknown field":          with("roles", []string{"Administrator"}),
		"oversized identifier":   with("session_id", "ses_"+strings.Repeat("0", MaxActorBytes)),
		"recorded text as actor": with("principal_id", edge.alpha.recorded()),
	}
	for name, actor := range cases {
		before := edge.eventCount()
		response := runRequests(t, edge.processor,
			actorFrame(t, "malformed", "principal.create",
				principalCreateParameters(edge.alpha.TenantID, "mallory@example.com"), actor),
		)[0]
		if response.OK || response.Error == nil || response.Error.Code != ErrorInvalidActor {
			t.Fatalf("%s: response = %#v, want %s", name, response.Error, ErrorInvalidActor)
		}
		assertRefusedWithoutWriting(t, edge, before, response, ErrorInvalidActor)
	}
}

func TestOversizedActorIsRefusedBeforeItIsRead(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	before := edge.eventCount()
	padding := strings.Repeat(" ", MaxActorBytes)
	frame := `{"protocol_version":"1","request_id":"padded-actor","operation":"principal.create",` +
		`"parameters":` + string(mustMarshal(t, principalCreateParameters(edge.alpha.TenantID, "carol@example.com"))) + `,` +
		`"actor":{"tenant_id":"` + edge.alpha.TenantID + `","principal_id":"` + edge.alpha.PrincipalID +
		`","session_id":"` + edge.alpha.SessionID + `"` + padding + `}}`
	response := runRequests(t, edge.processor, frame)[0]
	assertRefusedWithoutWriting(t, edge, before, response, ErrorInvalidActor)
}

func TestDuplicateFieldInsideTheActorIsAnInvalidRequest(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	before := edge.eventCount()
	frame := `{"protocol_version":"1","request_id":"duplicate-actor","operation":"principal.suspend",` +
		`"parameters":{"principal_id":"` + edge.alpha.PrincipalID + `"},` +
		`"actor":{"tenant_id":"` + edge.alpha.TenantID + `","principal_id":"` + edge.alpha.PrincipalID +
		`","session_id":"` + edge.alpha.SessionID + `","tenant_id":"` + edge.beta.TenantID + `"}}`
	response := runRequests(t, edge.processor, frame)[0]
	assertRefusedWithoutWriting(t, edge, before, response, ErrorInvalidRequest)
}

func TestActorWithoutALiveSessionIsRefused(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	unknownSession := edge.alpha
	unknownSession.SessionID = "ses_00000000000000000000000000000000"
	borrowedSession := edge.alpha
	borrowedSession.SessionID = edge.beta.SessionID
	foreignTenant := edge.alpha
	foreignTenant.TenantID = edge.beta.TenantID

	for name, actor := range map[string]actorFixture{
		"unknown session":                 unknownSession,
		"another principal's session":     borrowedSession,
		"tenant other than the session's": foreignTenant,
	} {
		before := edge.eventCount()
		response := runRequests(t, edge.processor,
			actorFrame(t, "no-session", "principal.create",
				principalCreateParameters(edge.alpha.TenantID, "mallory@example.com"), actor),
		)[0]
		if response.OK || response.Error.Code != ErrorActorSessionInvalid {
			t.Fatalf("%s: response = %#v", name, response.Error)
		}
		assertRefusedWithoutWriting(t, edge, before, response, ErrorActorSessionInvalid)
	}
}

func TestActorRefusedOnceItsSessionStopsStanding(t *testing.T) {
	t.Parallel()

	revoked := newActorEdge(t)
	if err := revoked.service.SessionRevoke(context.Background(), revoked.alpha.SessionID, "test", actorTestSetup); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	before := revoked.eventCount()
	response := runRequests(t, revoked.processor,
		actorFrame(t, "revoked", "role.create", map[string]any{
			"tenant_id":   revoked.alpha.TenantID,
			"name":        "reader",
			"permissions": []map[string]string{{"action": "doc:read", "resource": "*"}},
		}, revoked.alpha),
	)[0]
	assertRefusedWithoutWriting(t, revoked, before, response, ErrorActorSessionInvalid)

	suspended := newActorEdge(t)
	if _, err := suspended.service.PrincipalSuspend(context.Background(), suspended.alpha.PrincipalID, actorTestSetup); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}
	before = suspended.eventCount()
	response = runRequests(t, suspended.processor,
		actorFrame(t, "suspended", "principal.create",
			principalCreateParameters(suspended.alpha.TenantID, "mallory@example.com"), suspended.alpha),
	)[0]
	assertRefusedWithoutWriting(t, suspended, before, response, ErrorActorSessionInvalid)
}

func TestActorCannotWriteIntoAnotherTenant(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	before := edge.eventCount()
	responses := runRequests(t, edge.processor,
		actorFrame(t, "spoof-create", "principal.create",
			principalCreateParameters(edge.beta.TenantID, "mallory@example.com"), edge.alpha),
		actorFrame(t, "spoof-suspend", "principal.suspend",
			map[string]any{"principal_id": edge.beta.PrincipalID}, edge.alpha),
		actorFrame(t, "spoof-revoke", "session.revoke",
			map[string]any{"session_id": edge.beta.SessionID}, edge.alpha),
	)
	for _, response := range responses {
		assertRefusedWithoutWriting(t, edge, before, response, ErrorActorTenantMismatch)
	}

	if _, err := edge.service.SessionVerify(edge.beta.SessionID, edge.beta.secret); err != nil {
		t.Fatalf("the other tenant's session no longer verifies: %v", err)
	}
	principal, err := edge.service.PrincipalGetByID(edge.beta.PrincipalID)
	if err != nil || principal.Status != principaldomain.StatusActive {
		t.Fatalf("the other tenant's principal = %#v, %v", principal, err)
	}
}

func TestActorNeverChangesWhatIsAllowed(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	setup := runRequests(t, edge.processor,
		actorFrame(t, "admin-role", "role.create", map[string]any{
			"tenant_id":   edge.alpha.TenantID,
			"name":        "administrator",
			"permissions": []map[string]string{{"action": "*", "resource": "*"}},
		}, nil),
	)[0]
	var role struct {
		ID string `json:"role_id"`
	}
	decodeResult(t, setup.Result, &role)
	granted := runRequests(t, edge.processor,
		actorFrame(t, "admin-grant", "grant.create", map[string]any{
			"tenant_id": edge.alpha.TenantID, "principal_id": edge.alpha.PrincipalID, "role_id": role.ID,
		}, nil),
	)[0]
	if !granted.OK {
		t.Fatalf("grant.create = %#v", granted.Error)
	}

	operations := []struct {
		operation  string
		parameters map[string]any
		want       string
	}{
		{"authorize.decide", map[string]any{
			"tenant_id": edge.beta.TenantID, "principal_id": edge.beta.PrincipalID,
			"action": "doc:read", "resource": "file:a",
		}, "deny:" + identity.ReasonDenyNoGrant},
		{"session.verify", map[string]any{"session_id": edge.beta.SessionID, "session_secret": "guess"},
			"error:" + ErrorSessionNotFound},
		{"grant.revoke", map[string]any{"grant_id": "grt_00000000000000000000000000000000"},
			"error:" + ErrorGrantNotFound},
	}
	for _, entry := range operations {
		plain := runRequests(t, edge.processor, actorFrame(t, "plain", entry.operation, entry.parameters, nil))[0]
		attributed := runRequests(t, edge.processor, actorFrame(t, "attributed", entry.operation, entry.parameters, edge.alpha))[0]
		if outcome(t, plain) != entry.want || outcome(t, attributed) != entry.want {
			t.Fatalf("%s: unattributed %s, attributed %s, want %s",
				entry.operation, outcome(t, plain), outcome(t, attributed), entry.want)
		}
	}
}

func outcome(t *testing.T, response Response) string {
	t.Helper()

	if response.Error != nil {
		return "error:" + response.Error.Code
	}
	var decision identity.Decision
	if err := json.Unmarshal(mustMarshal(t, response.Result), &decision); err == nil && decision.Decision != "" {
		return decision.Decision + ":" + decision.ReasonCode
	}
	return "ok"
}

func TestReadWithActorRecordsNothing(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	before := edge.eventCount()
	response := runRequests(t, edge.processor,
		actorFrame(t, "read", "tenant.get", map[string]any{"tenant_id": edge.alpha.TenantID}, edge.alpha),
	)[0]
	if !response.OK {
		t.Fatalf("attributed tenant.get = %#v", response.Error)
	}
	if edge.eventCount() != before {
		t.Fatal("an attributed read appended an event")
	}
}

func TestStandardsDispatchRefusesAnActor(t *testing.T) {
	t.Parallel()

	edge := newActorEdge(t)
	before := edge.eventCount()
	response := runRequests(t, edge.processor,
		actorFrame(t, "standards", "standards.dispatch", map[string]any{
			"contract_version": StandardsContractVersion,
			"endpoint":         "oidc.jwks",
			"method":           "GET",
		}, edge.alpha),
	)[0]
	assertRefusedWithoutWriting(t, edge, before, response, ErrorInvalidActor)
}

func TestActorWithoutStorageFailsClosed(t *testing.T) {
	t.Parallel()

	processor := New(system.New(buildinfo.New("", "", "")), nil)
	wellFormed := actorFixture{
		TenantID:    "tnt_00000000000000000000000000000000",
		PrincipalID: "prn_00000000000000000000000000000000",
		SessionID:   "ses_00000000000000000000000000000000",
	}
	responses := runRequests(t, processor,
		actorFrame(t, "ping", "system.ping", map[string]any{}, wellFormed),
		actorFrame(t, "ping-bad", "system.ping", map[string]any{}, map[string]any{"tenant_id": "x"}),
	)
	assertErrorCode(t, responses[0], ErrorStorageNotConfigured)
	assertErrorCode(t, responses[1], ErrorInvalidActor)
}
