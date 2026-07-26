package identity

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

func bootstrapService(t *testing.T) (*Service, *memoryLedger, string) {
	t.Helper()

	ledger := &memoryLedger{}
	service, err := New(ledger, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	created, err := service.Bootstrap(context.Background(), "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	return service, ledger, created.Tenant.ID
}

func TestPrincipalCreateClaimsIdentifierExactlyOnce(t *testing.T) {
	t.Parallel()

	service, ledger, tenantID := bootstrapService(t)

	created, err := service.PrincipalCreate(
		context.Background(),
		tenantID,
		principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "  Alice@Example.COM "},
		"test",
	)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if created.Identifier.Value != "alice@example.com" || created.Status != "active" {
		t.Fatalf("PrincipalCreate() = %#v", created)
	}

	_, err = service.PrincipalCreate(
		context.Background(),
		tenantID,
		principaldomain.KindWorkload,
		principaldomain.Identifier{Namespace: "email", Value: "ALICE@example.com"},
		"test",
	)
	if !errors.Is(err, ErrIdentifierConflict) {
		t.Fatalf("duplicate PrincipalCreate() error = %v, want ErrIdentifierConflict", err)
	}

	// Same value in a different namespace is a distinct claim.
	if _, err := service.PrincipalCreate(
		context.Background(),
		tenantID,
		principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "login", Value: "alice@example.com"},
		"test",
	); err != nil {
		t.Fatalf("cross-namespace PrincipalCreate() error = %v", err)
	}
	if len(ledger.events) != 3 {
		t.Fatalf("ledger holds %d events, want 3", len(ledger.events))
	}

	if _, err := service.PrincipalCreate(
		context.Background(),
		"tnt_00000000000000000000000000000000",
		principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "bob@example.com"},
		"test",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown-tenant PrincipalCreate() error = %v", err)
	}
}

func TestConcurrentPrincipalCreateHasOneWinner(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	identifier := principaldomain.Identifier{Namespace: "email", Value: "race@example.com"}

	const attempts = 100
	var winners, conflicts atomic.Int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := service.PrincipalCreate(
				context.Background(),
				tenantID,
				principaldomain.KindHuman,
				identifier,
				"test",
			)
			switch {
			case err == nil:
				winners.Add(1)
			case errors.Is(err, ErrIdentifierConflict):
				conflicts.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if winners.Load() != 1 || conflicts.Load() != attempts-1 {
		t.Fatalf("winners = %d, conflicts = %d", winners.Load(), conflicts.Load())
	}
}

func TestPrincipalSuspendIsDurableAndIdempotent(t *testing.T) {
	t.Parallel()

	service, ledger, tenantID := bootstrapService(t)
	created, err := service.PrincipalCreate(
		context.Background(),
		tenantID,
		principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "alice@example.com"},
		"test",
	)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	suspended, err := service.PrincipalSuspend(context.Background(), created.ID, "test")
	if err != nil || suspended.Status != principaldomain.StatusSuspended {
		t.Fatalf("PrincipalSuspend() = %#v, %v", suspended, err)
	}
	eventsAfterFirst := len(ledger.events)
	repeated, err := service.PrincipalSuspend(context.Background(), created.ID, "test")
	if err != nil || repeated.Status != principaldomain.StatusSuspended {
		t.Fatalf("repeat PrincipalSuspend() = %#v, %v", repeated, err)
	}
	if len(ledger.events) != eventsAfterFirst {
		t.Fatal("repeat suspension appended a second event")
	}

	// Replay from the ledger alone preserves the deny state.
	rebuilt, err := New(nil, ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	replayed, err := rebuilt.PrincipalGetByID(created.ID)
	if err != nil || replayed.Status != principaldomain.StatusSuspended {
		t.Fatalf("replayed principal = %#v, %v", replayed, err)
	}

	if _, err := service.PrincipalSuspend(
		context.Background(),
		"prn_00000000000000000000000000000000",
		"test",
	); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("unknown PrincipalSuspend() error = %v", err)
	}
}

func TestPrincipalQueriesAndSnapshotRoundTrip(t *testing.T) {
	t.Parallel()

	service, ledger, tenantID := bootstrapService(t)
	snapshots := &memorySnapshots{}
	service.UseSnapshots(snapshots)

	created, err := service.PrincipalCreate(
		context.Background(),
		tenantID,
		principaldomain.KindWorkload,
		principaldomain.Identifier{Namespace: "login", Value: "ci-runner"},
		"test",
	)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	byIdentifier, err := service.PrincipalGetByIdentifier(tenantID, principaldomain.Identifier{
		Namespace: "login",
		Value:     "CI-Runner",
	})
	if err != nil || byIdentifier.ID != created.ID {
		t.Fatalf("PrincipalGetByIdentifier() = %#v, %v", byIdentifier, err)
	}
	if _, err := service.PrincipalGetByIdentifier(tenantID, principaldomain.Identifier{
		Namespace: "login",
		Value:     "missing",
	}); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("missing PrincipalGetByIdentifier() error = %v", err)
	}

	// The snapshot written after the create seeds an equivalent projection.
	restored, err := NewFromSnapshot(nil, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	fromSnapshot, err := restored.PrincipalGetByID(created.ID)
	if err != nil || fromSnapshot.Identifier.Value != "ci-runner" {
		t.Fatalf("snapshot principal = %#v, %v", fromSnapshot, err)
	}

	// Full replay agrees with the snapshot-seeded projection.
	replayed, err := New(nil, ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	left, _ := replayed.PrincipalGetByID(created.ID)
	if left != fromSnapshot {
		t.Fatalf("replay/snapshot divergence: %#v vs %#v", left, fromSnapshot)
	}
}
