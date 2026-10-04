package identity

import (
	"context"
	"errors"

	"github.com/d31ma/sesame/internal/domain/audit"
)

// ErrActorTenantMismatch reports a write whose event belongs to a tenant
// other than the attributed principal's own tenant.
var ErrActorTenantMismatch = errors.New("actor belongs to a different tenant than the event it would record")

type actorTenantLedger struct {
	ledger Ledger
}

func guardActorTenant(ledger Ledger) Ledger {
	if ledger == nil {
		return nil
	}
	return actorTenantLedger{ledger: ledger}
}

func (l actorTenantLedger) Append(
	ctx context.Context,
	eventType string,
	tenantID string,
	actor string,
	payload any,
) (audit.Event, error) {
	if err := requireActorTenant(tenantID, actor); err != nil {
		return audit.Event{}, err
	}
	return l.ledger.Append(ctx, eventType, tenantID, actor, payload)
}

// requireActorTenant refuses an attributed principal actor whose tenant is not
// tenantID. The ledger applies it to every event. A write also applies it as
// soon as it knows the tenant of its target, before any answer that depends
// on the target's state: an idempotent no-op (already revoked, suspended,
// disabled, withdrawn, deprovisioned) or a state refusal (already exists,
// already a member, not enrolled). An attributed caller therefore gets the
// same actor_tenant_mismatch for every record of another tenant, whatever
// state it is in. Operator actors pass unchanged.
func requireActorTenant(tenantID, actor string) error {
	if !audit.IsPrincipalActor(actor) {
		return nil
	}
	parsed, err := audit.ParsePrincipalActor(actor)
	if err != nil || parsed.TenantID != tenantID {
		return ErrActorTenantMismatch
	}
	return nil
}
