package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

type actorFixture struct {
	authenticationFixture
	actor audit.PrincipalActor
}

func newActorFixture(t *testing.T) actorFixture {
	t.Helper()

	fixture := newAuthenticationFixture(t)
	ctx := context.Background()
	begun, err := fixture.service.AuthenticationBegin(ctx, fixture.tenant, fixture.identity, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := fixture.service.AuthenticationVerifyPassword(ctx, begun.TransactionID, goodPassword, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	return actorFixture{
		authenticationFixture: fixture,
		actor: audit.PrincipalActor{
			TenantID:    issued.TenantID,
			PrincipalID: issued.PrincipalID,
			SessionID:   issued.SessionID,
		},
	}
}

func TestVerifyActorAcceptsALiveSessionOfThatPrincipal(t *testing.T) {
	t.Parallel()

	fixture := newActorFixture(t)
	if err := fixture.service.VerifyActor(fixture.actor); err != nil {
		t.Fatalf("VerifyActor() error = %v", err)
	}
}

func TestVerifyActorRefusesAnInconsistentAttribution(t *testing.T) {
	t.Parallel()

	fixture := newActorFixture(t)
	otherTenant, err := fixture.service.Bootstrap(context.Background(), "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	bob, err := fixture.service.PrincipalCreate(context.Background(), fixture.tenant, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "bob@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	unknownSession := fixture.actor
	unknownSession.SessionID = "ses_00000000000000000000000000000000"
	otherPrincipal := fixture.actor
	otherPrincipal.PrincipalID = bob.ID
	foreignTenant := fixture.actor
	foreignTenant.TenantID = otherTenant.Tenant.ID

	for name, actor := range map[string]audit.PrincipalActor{
		"unknown session":                unknownSession,
		"session of another principal":   otherPrincipal,
		"tenant other than the session's": foreignTenant,
	} {
		if err := fixture.service.VerifyActor(actor); !errors.Is(err, ErrActorSessionInvalid) {
			t.Fatalf("VerifyActor(%s) error = %v, want ErrActorSessionInvalid", name, err)
		}
	}
}

func TestVerifyActorRefusesASessionThatNoLongerStands(t *testing.T) {
	t.Parallel()

	expired := newActorFixture(t)
	expired.service.UseClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	if err := expired.service.VerifyActor(expired.actor); !errors.Is(err, ErrActorSessionInvalid) {
		t.Fatalf("VerifyActor(expired) error = %v", err)
	}

	revoked := newActorFixture(t)
	if err := revoked.service.SessionRevoke(context.Background(), revoked.actor.SessionID, "test", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}
	if err := revoked.service.VerifyActor(revoked.actor); !errors.Is(err, ErrActorSessionInvalid) {
		t.Fatalf("VerifyActor(revoked) error = %v", err)
	}

	suspended := newActorFixture(t)
	if _, err := suspended.service.PrincipalSuspend(context.Background(), suspended.alice, "test"); err != nil {
		t.Fatalf("PrincipalSuspend() error = %v", err)
	}
	if err := suspended.service.VerifyActor(suspended.actor); !errors.Is(err, ErrActorSessionInvalid) {
		t.Fatalf("VerifyActor(suspended) error = %v", err)
	}
}

func TestPrincipalActorCannotWriteIntoAnotherTenant(t *testing.T) {
	t.Parallel()

	fixture := newActorFixture(t)
	otherTenant, err := fixture.service.Bootstrap(context.Background(), "other", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	before := len(fixture.ledger.events)

	_, err = fixture.service.PrincipalCreate(context.Background(), otherTenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "mallory@example.com"}, fixture.actor.String())
	if !errors.Is(err, ErrActorTenantMismatch) {
		t.Fatalf("PrincipalCreate(cross-tenant actor) error = %v, want ErrActorTenantMismatch", err)
	}
	if len(fixture.ledger.events) != before {
		t.Fatalf("a refused cross-tenant write appended %d events", len(fixture.ledger.events)-before)
	}
	if _, err := fixture.service.PrincipalGetByIdentifier(otherTenant.Tenant.ID,
		principaldomain.Identifier{Namespace: "email", Value: "mallory@example.com"}); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("refused principal is visible: %v", err)
	}
}

func TestMalformedPrincipalActorTextNeverReachesTheLedger(t *testing.T) {
	t.Parallel()

	fixture := newActorFixture(t)
	before := len(fixture.ledger.events)
	_, err := fixture.service.PrincipalSuspend(context.Background(), fixture.alice, "principal:"+fixture.tenant)
	if !errors.Is(err, ErrActorTenantMismatch) {
		t.Fatalf("PrincipalSuspend(malformed actor) error = %v, want ErrActorTenantMismatch", err)
	}
	if len(fixture.ledger.events) != before {
		t.Fatal("a malformed principal actor was recorded")
	}
}

func TestPrincipalActorWritesInsideItsOwnTenant(t *testing.T) {
	t.Parallel()

	fixture := newActorFixture(t)
	_, err := fixture.service.PrincipalCreate(context.Background(), fixture.tenant, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "carol@example.com"}, fixture.actor.String())
	if err != nil {
		t.Fatalf("PrincipalCreate(own tenant) error = %v", err)
	}
	last := fixture.ledger.events[len(fixture.ledger.events)-1]
	if last.Actor != fixture.actor.String() || last.TenantID != fixture.tenant {
		t.Fatalf("recorded actor %q in tenant %q", last.Actor, last.TenantID)
	}
}
