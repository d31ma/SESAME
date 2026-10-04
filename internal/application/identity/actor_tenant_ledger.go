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
