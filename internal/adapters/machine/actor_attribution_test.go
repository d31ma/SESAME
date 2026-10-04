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
