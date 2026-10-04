package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/d31ma/sesame/internal/domain/audit"
	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// An attributed write aimed at another tenant's record must answer
// actor_tenant_mismatch whatever state the record is in. Before the guard ran
// ahead of these answers, a record already in its target state (revoked,
// suspended, disabled) answered success, and a record in a conflicting state
// answered its own error, so an attributed caller could read another
// tenant's state from the answer.

const actorTenantProbeOwner = "test"

type actorTenantProbe struct {
	service *Service
	tenant  string
	write   func(actor string) error
	ownErr  error
}

func attributedActor(tenantID string) string {
	return audit.PrincipalActor{
		TenantID:    tenantID,
		PrincipalID: "prn_00000000000000000000000000000001",
		SessionID:   "ses_00000000000000000000000000000002",
	}.String()
}

func ledgerLength(t *testing.T, service *Service) int {
	t.Helper()
	guarded, ok := service.ledger.(actorTenantLedger)
	if !ok {
		t.Fatalf("ledger is %T, want actorTenantLedger", service.ledger)
	}
	memory, ok := guarded.ledger.(*memoryLedger)
	if !ok {
		t.Fatalf("ledger is %T, want *memoryLedger", guarded.ledger)
	}
	return len(memory.events)
}

func requireNoStep(t *testing.T, step error, name string) {
	t.Helper()
	if step != nil {
		t.Fatalf("%s: %v", name, step)
	}
}

func assertActorTenantProbe(t *testing.T, probe actorTenantProbe) {
	t.Helper()
	elsewhere, err := probe.service.Bootstrap(context.Background(), "elsewhere", actorTenantProbeOwner)
	requireNoStep(t, err, "Bootstrap(elsewhere)")
	before := ledgerLength(t, probe.service)

	foreign := probe.write(attributedActor(elsewhere.Tenant.ID))
	if !errors.Is(foreign, ErrActorTenantMismatch) {
		t.Fatalf("attributed write from another tenant error = %v, want ErrActorTenantMismatch", foreign)
	}
	own := probe.write(attributedActor(probe.tenant))
	if !errors.Is(own, probe.ownErr) || (probe.ownErr == nil && own != nil) {
		t.Fatalf("attributed write from the record's tenant error = %v, want %v", own, probe.ownErr)
	}
	if after := ledgerLength(t, probe.service); after != before {
		t.Fatalf("no-op writes appended %d events", after-before)
	}
}

func TestAttributedRevokeOfARevokedSessionChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newActorFixture(t)
	ctx := context.Background()
	requireNoStep(t, fixture.service.SessionRevoke(ctx, fixture.actor.SessionID, "", actorTenantProbeOwner), "SessionRevoke")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenant, write: func(actor string) error {
		return fixture.service.SessionRevoke(ctx, fixture.actor.SessionID, "", actor)
	}})
}

func TestAttributedSuspendOfASuspendedPrincipalChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newAuthenticationFixture(t)
	ctx := context.Background()
	_, err := fixture.service.PrincipalSuspend(ctx, fixture.alice, actorTenantProbeOwner)
	requireNoStep(t, err, "PrincipalSuspend")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenant, write: func(actor string) error {
		_, err := fixture.service.PrincipalSuspend(ctx, fixture.alice, actor)
		return err
	}})
}

func TestAttributedBootstrapOfAnExistingTenantChecksTheTenant(t *testing.T) {
	t.Parallel()
	service, _, tenantID := bootstrapService(t)
	tenant, err := service.GetByID(tenantID)
	requireNoStep(t, err, "GetByID")

	assertActorTenantProbe(t, actorTenantProbe{service: service, tenant: tenantID, write: func(actor string) error {
		_, err := service.Bootstrap(context.Background(), tenant.Name, actor)
		return err
	}})
}

func TestAttributedDisableOfADisabledClientChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newFlowFixture(t)
	ctx := context.Background()
	requireNoStep(t, fixture.service.ClientDisable(ctx, fixture.clientID, "", actorTenantProbeOwner), "ClientDisable")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		return fixture.service.ClientDisable(ctx, fixture.clientID, "", actor)
	}})
}

func TestAttributedRotationOfADisabledClientChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newFlowFixture(t)
	ctx := context.Background()
	requireNoStep(t, fixture.service.ClientDisable(ctx, fixture.clientID, "", actorTenantProbeOwner), "ClientDisable")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, ownErr: ErrClientDisabled,
		write: func(actor string) error {
			_, err := fixture.service.ClientRotateSecret(ctx, fixture.clientID, actor)
			return err
		}})
}

func TestAttributedRevokeOfARevokedRefreshFamilyChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture, _ := offlineFixture(t)
	ctx := context.Background()
	familyID := fixture.onlyFamily(t)
	requireNoStep(t, fixture.service.RefreshFamilyRevoke(ctx, familyID, "", actorTenantProbeOwner), "RefreshFamilyRevoke")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		return fixture.service.RefreshFamilyRevoke(ctx, familyID, "", actor)
	}})
}

func TestAttributedWithdrawalOfAWithdrawnConsentChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newFlowFixture(t)
	ctx := context.Background()
	_, err := fixture.service.ConsentGrant(ctx, fixture.sessionID, fixture.sessionKey, fixture.clientID,
		[]string{"profile"}, actorTenantProbeOwner)
	requireNoStep(t, err, "ConsentGrant")
	requireNoStep(t, fixture.service.ConsentWithdraw(ctx, fixture.principalID, fixture.clientID, actorTenantProbeOwner),
		"ConsentWithdraw")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		return fixture.service.ConsentWithdraw(ctx, fixture.principalID, fixture.clientID, actor)
	}})
}

func TestAttributedDisableOfADisabledProviderChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newFedFixture(t, "")
	ctx := context.Background()
	requireNoStep(t, fixture.service.ProviderDisable(ctx, fixture.tenantID, fixture.providerID, "", actorTenantProbeOwner),
		"ProviderDisable")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		return fixture.service.ProviderDisable(ctx, fixture.tenantID, fixture.providerID, "", actor)
	}})
}

func TestAttributedDisableOfADisabledSAMLProviderChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newSAMLFixture(t, "")
	ctx := context.Background()
	requireNoStep(t, fixture.service.SAMLProviderDisable(ctx, fixture.tenantID, fixture.providerID, "", actorTenantProbeOwner),
		"SAMLProviderDisable")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		return fixture.service.SAMLProviderDisable(ctx, fixture.tenantID, fixture.providerID, "", actor)
	}})
}

func TestAttributedDisableOfADisabledProvisioningClientChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newSCIMFixture(t)
	ctx := context.Background()
	requireNoStep(t, fixture.service.ProvisioningClientDisable(ctx, fixture.tenantID, fixture.client.ID, "", actorTenantProbeOwner),
		"ProvisioningClientDisable")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		return fixture.service.ProvisioningClientDisable(ctx, fixture.tenantID, fixture.client.ID, "", actor)
	}})
}

func TestAttributedDeprovisionOfADeprovisionedUserChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newSCIMFixture(t)
	ctx := context.Background()
	user, err := fixture.service.UserProvision(ctx, fixture.client, scimUserPayload(t, nil), actorTenantProbeOwner)
	requireNoStep(t, err, "UserProvision")
	requireNoStep(t, fixture.service.UserDeprovision(ctx, fixture.client, user.ID, actorTenantProbeOwner), "UserDeprovision")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		return fixture.service.UserDeprovision(ctx, fixture.client, user.ID, actor)
	}})
}

func TestAttributedDeprovisionOfAnEmptiedGroupChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newGroupFixture(t, true)
	ctx := context.Background()
	group, err := fixture.service.GroupProvision(ctx, fixture.client, groupPayload(t, "engineering", fixture.first),
		actorTenantProbeOwner)
	requireNoStep(t, err, "GroupProvision")
	requireNoStep(t, fixture.service.GroupDeprovision(ctx, fixture.client, group.ID, actorTenantProbeOwner), "GroupDeprovision")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		return fixture.service.GroupDeprovision(ctx, fixture.client, group.ID, actor)
	}})
}

func TestAttributedMembershipChangesCheckTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newAuthenticationFixture(t)
	ctx := context.Background()
	group, err := fixture.service.GroupCreate(ctx, fixture.tenant, "readers", actorTenantProbeOwner)
	requireNoStep(t, err, "GroupCreate")
	requireNoStep(t, fixture.service.GroupMemberAdd(ctx, group.ID, fixture.alice, actorTenantProbeOwner), "GroupMemberAdd")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenant, ownErr: ErrGroupMemberExists,
		write: func(actor string) error {
			return fixture.service.GroupMemberAdd(ctx, group.ID, fixture.alice, actor)
		}})
}

func TestAttributedActivationWithoutEnrollmentChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newAuthenticationFixture(t)

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenant, ownErr: ErrTOTPNotEnrolled,
		write: func(actor string) error {
			return fixture.service.TOTPActivate(context.Background(), fixture.alice, "000000", actor)
		}})
}

func TestAttributedCreationOfATakenNameChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newAuthenticationFixture(t)
	ctx := context.Background()
	permissions := []authzdomain.Permission{{Action: "doc:read", Resource: "file:*"}}
	_, err := fixture.service.RoleCreate(ctx, fixture.tenant, "reader", permissions, actorTenantProbeOwner)
	requireNoStep(t, err, "RoleCreate")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenant, ownErr: ErrRoleExists,
		write: func(actor string) error {
			_, err := fixture.service.RoleCreate(ctx, fixture.tenant, "reader", permissions, actor)
			return err
		}})
}

func TestAttributedCreationOfAClaimedIdentifierChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newAuthenticationFixture(t)

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenant, ownErr: ErrIdentifierConflict,
		write: func(actor string) error {
			_, err := fixture.service.PrincipalCreate(context.Background(), fixture.tenant, principaldomain.KindHuman,
				fixture.identity, actor)
			return err
		}})
}

func TestAttributedDeviceDenialChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture := newDeviceFixture(t)
	ctx := context.Background()
	requireNoStep(t, fixture.service.DeviceAuthorizationDeny(ctx, fixture.tenantID, fixture.device.UserCode, actorTenantProbeOwner),
		"DeviceAuthorizationDeny")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, ownErr: ErrUserCodeNotFound,
		write: func(actor string) error {
			return fixture.service.DeviceAuthorizationDeny(ctx, fixture.tenantID, fixture.device.UserCode, actor)
		}})
}

func TestAttributedRevocationOfARevokedRefreshTokenChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture, tokens := offlineFixture(t)
	ctx := context.Background()
	requireNoStep(t, fixture.service.RefreshFamilyRevoke(ctx, fixture.onlyFamily(t), "", actorTenantProbeOwner),
		"RefreshFamilyRevoke")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		return fixture.service.Revoke(ctx, fixture.refreshRequest(tokens.RefreshToken, ""), tokens.RefreshToken, actor)
	}})
}

func TestAttributedLogoutOfAnEndedSessionChecksTheTenant(t *testing.T) {
	t.Parallel()
	fixture, tokens := offlineFixture(t)
	ctx := context.Background()
	requireNoStep(t, fixture.service.SessionRevoke(ctx, fixture.sessionID, "", actorTenantProbeOwner), "SessionRevoke")

	assertActorTenantProbe(t, actorTenantProbe{service: fixture.service, tenant: fixture.tenantID, write: func(actor string) error {
		_, err := fixture.service.Logout(ctx, LogoutRequest{IDTokenHint: tokens.IDToken}, actor)
		return err
	}})
}
