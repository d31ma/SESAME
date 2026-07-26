package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/d31ma/sesame/internal/domain/audit"
)

// memoryLedger implements Ledger with the same chaining rules as the FYLO
// ledger, entirely in memory.
type memoryLedger struct {
	events  []audit.Event
	failing bool
}

func (l *memoryLedger) Append(
	_ context.Context,
	eventType string,
	tenantID string,
	actor string,
	payload any,
) (audit.Event, error) {
	if l.failing {
		return audit.Event{}, errors.New("synthetic storage failure")
	}
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

func TestBootstrapCreatesExactlyOnce(t *testing.T) {
	t.Parallel()

	ledger := &memoryLedger{}
	service, err := New(ledger, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	created, err := service.Bootstrap(context.Background(), "  Acme-Corp ", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if !created.Created || created.Tenant.Name != "acme-corp" || created.Tenant.Status != "active" {
		t.Fatalf("Bootstrap() = %#v", created)
	}

	repeated, err := service.Bootstrap(context.Background(), "ACME-CORP", "test")
	if err != nil {
		t.Fatalf("repeat Bootstrap() error = %v", err)
	}
	if repeated.Created || repeated.Tenant.ID != created.Tenant.ID {
		t.Fatalf("repeat Bootstrap() = %#v", repeated)
	}
	if len(ledger.events) != 1 {
		t.Fatalf("ledger holds %d events, want 1", len(ledger.events))
	}
}

func TestBootstrapValidatesInput(t *testing.T) {
	t.Parallel()

	service, err := New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := service.Bootstrap(context.Background(), "bad name!", "test"); err == nil {
		t.Fatal("Bootstrap() accepted an invalid name")
	}
	if _, err := service.Bootstrap(context.Background(), "acme", ""); err == nil {
		t.Fatal("Bootstrap() accepted an empty actor")
	}
}

func TestBootstrapWrapsStorageFailures(t *testing.T) {
	t.Parallel()

	service, err := New(&memoryLedger{failing: true}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = service.Bootstrap(context.Background(), "acme", "test")
	if !errors.Is(err, ErrStorageFailure) {
		t.Fatalf("Bootstrap() error = %v, want ErrStorageFailure", err)
	}
}

func TestProjectionRebuildsFromReplay(t *testing.T) {
	t.Parallel()

	ledger := &memoryLedger{}
	service, err := New(ledger, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	created, err := service.Bootstrap(context.Background(), "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	rebuilt, err := New(ledger, ledger.events)
	if err != nil {
		t.Fatalf("New(replayed) error = %v", err)
	}
	byName, err := rebuilt.GetByName("acme")
	if err != nil || byName.ID != created.Tenant.ID {
		t.Fatalf("GetByName() = %#v, %v", byName, err)
	}
	byID, err := rebuilt.GetByID(created.Tenant.ID)
	if err != nil || byID.Name != "acme" {
		t.Fatalf("GetByID() = %#v, %v", byID, err)
	}
	if _, err := rebuilt.GetByName("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByName(missing) error = %v, want ErrNotFound", err)
	}
	if _, err := rebuilt.GetByID("tnt_00000000000000000000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByID(missing) error = %v, want ErrNotFound", err)
	}
}

type memorySnapshots struct {
	states []json.RawMessage
}

func (m *memorySnapshots) WriteSnapshot(_ context.Context, state any) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	m.states = append(m.states, encoded)
	return nil
}

func TestSnapshotStateRoundTrip(t *testing.T) {
	t.Parallel()

	ledger := &memoryLedger{}
	snapshots := &memorySnapshots{}
	service, err := New(ledger, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	service.UseSnapshots(snapshots)

	first, err := service.Bootstrap(context.Background(), "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if len(snapshots.states) != 1 {
		t.Fatalf("snapshot writes = %d, want 1", len(snapshots.states))
	}

	// Seed a fresh service from the snapshot alone, then from snapshot plus a
	// tail event.
	restored, err := NewFromSnapshot(ledger, snapshots.states[0], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	byName, err := restored.GetByName("acme")
	if err != nil || byName.ID != first.Tenant.ID {
		t.Fatalf("restored GetByName() = %#v, %v", byName, err)
	}

	tailLedger := &memoryLedger{}
	tailService, err := New(tailLedger, nil)
	if err != nil {
		t.Fatalf("tail New() error = %v", err)
	}
	if _, err := tailService.Bootstrap(context.Background(), "tail-corp", "test"); err != nil {
		t.Fatalf("tail Bootstrap() error = %v", err)
	}
	combined, err := NewFromSnapshot(ledger, snapshots.states[0], tailLedger.events)
	if err != nil {
		t.Fatalf("NewFromSnapshot(tail) error = %v", err)
	}
	for _, name := range []string{"acme", "tail-corp"} {
		if _, err := combined.GetByName(name); err != nil {
			t.Fatalf("combined GetByName(%s) error = %v", name, err)
		}
	}

	// Fail closed on unsupported or duplicate snapshot state.
	if _, err := NewFromSnapshot(ledger, json.RawMessage(`{"schema_version":2,"tenants":[]}`), nil); err == nil {
		t.Fatal("NewFromSnapshot() accepted an unsupported state version")
	}
	if _, err := NewFromSnapshot(ledger, snapshots.states[0], ledger.events); err == nil {
		t.Fatal("NewFromSnapshot() accepted a tail that duplicates the snapshot")
	}
}

func TestReplayFailsClosedOnCorruptTenantEvents(t *testing.T) {
	t.Parallel()

	ledger := &memoryLedger{}
	if _, err := ledger.Append(context.Background(), "tenant.bootstrapped", "tnt_x", "test", map[string]any{
		"tenant_id": "tnt_00000000000000000000000000000000",
		"name":      "acme",
		"status":    "active",
		"extra":     true,
	}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if _, err := New(ledger, ledger.events); err == nil {
		t.Fatal("New() accepted a tenant event with unknown payload fields")
	}

	duplicate := &memoryLedger{}
	for range 2 {
		if _, err := duplicate.Append(context.Background(), "tenant.bootstrapped", "tnt_x", "test", map[string]any{
			"tenant_id": "tnt_00000000000000000000000000000000",
			"name":      "acme",
			"status":    "active",
		}); err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}
	if _, err := New(duplicate, duplicate.events); err == nil {
		t.Fatal("New() accepted duplicate bootstrap events for one name")
	}
}
