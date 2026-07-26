package identity

import (
	"context"
	"testing"

	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

func TestAdminBootstrapConverges(t *testing.T) {
	t.Parallel()

	ledger := &memoryLedger{}
	service, err := New(ledger, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "Admin@Example.com"}

	first, err := service.AdminBootstrap(context.Background(), "Acme", identifier, "test")
	if err != nil {
		t.Fatalf("AdminBootstrap() error = %v", err)
	}
	if !first.Created || first.Role.Name != AdministratorRoleName ||
		first.Administrator.Identifier.Value != "admin@example.com" || first.Grant.ID == "" {
		t.Fatalf("AdminBootstrap() = %#v", first)
	}
	eventsAfterFirst := len(ledger.events)

	// The administrator can do anything in its tenant.
	decision, err := service.Decide(DecisionRequest{
		TenantID:    first.Tenant.ID,
		PrincipalID: first.Administrator.ID,
		Action:      "tenant:configure",
		Resource:    "deployment:root",
	}, nil)
	if err != nil || decision.Decision != DecisionAllow {
		t.Fatalf("administrator decision = %#v, %v", decision, err)
	}

	// Re-running converges without appending anything.
	second, err := service.AdminBootstrap(context.Background(), "acme", identifier, "test")
	if err != nil {
		t.Fatalf("repeat AdminBootstrap() error = %v", err)
	}
	if second.Created ||
		second.Tenant.ID != first.Tenant.ID ||
		second.Role.ID != first.Role.ID ||
		second.Administrator.ID != first.Administrator.ID ||
		second.Grant.ID != first.Grant.ID {
		t.Fatalf("repeat AdminBootstrap() = %#v", second)
	}
	if len(ledger.events) != eventsAfterFirst {
		t.Fatalf("repeat bootstrap appended %d events", len(ledger.events)-eventsAfterFirst)
	}

	// An interrupted bootstrap resumes: drop the projection and replay, then
	// bootstrap again against the same ledger.
	replayed, err := New(ledger, ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	resumed, err := replayed.AdminBootstrap(context.Background(), "acme", identifier, "test")
	if err != nil {
		t.Fatalf("resumed AdminBootstrap() error = %v", err)
	}
	if resumed.Created || resumed.Administrator.ID != first.Administrator.ID {
		t.Fatalf("resumed AdminBootstrap() = %#v", resumed)
	}

	// A second administrator identifier in the same tenant reuses the tenant
	// and role but creates its own principal and grant.
	other, err := service.AdminBootstrap(context.Background(), "acme", principaldomain.Identifier{
		Namespace: "email",
		Value:     "second@example.com",
	}, "test")
	if err != nil {
		t.Fatalf("second administrator AdminBootstrap() error = %v", err)
	}
	if !other.Created || other.Role.ID != first.Role.ID || other.Administrator.ID == first.Administrator.ID {
		t.Fatalf("second administrator = %#v", other)
	}
}

func TestAdminBootstrapValidatesInput(t *testing.T) {
	t.Parallel()

	service, err := New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := service.AdminBootstrap(context.Background(), "bad name!", principaldomain.Identifier{
		Namespace: "email",
		Value:     "admin@example.com",
	}, "test"); err == nil {
		t.Fatal("AdminBootstrap() accepted an invalid tenant name")
	}
	if _, err := service.AdminBootstrap(context.Background(), "acme", principaldomain.Identifier{
		Namespace: "",
		Value:     "admin@example.com",
	}, "test"); err == nil {
		t.Fatal("AdminBootstrap() accepted an invalid identifier")
	}
	if _, err := service.AdminBootstrap(context.Background(), "acme", principaldomain.Identifier{
		Namespace: "email",
		Value:     "admin@example.com",
	}, ""); err == nil {
		t.Fatal("AdminBootstrap() accepted an empty actor")
	}
}
