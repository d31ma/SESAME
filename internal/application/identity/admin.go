package identity

import (
	"context"
	"errors"
	"fmt"

	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
)

// AdministratorRoleName is the reserved role granted by AdminBootstrap.
const AdministratorRoleName = "administrator"

// AdminBootstrapResult reports what a bootstrap converged to.
type AdminBootstrapResult struct {
	Tenant        tenantdomain.Tenant       `json:"tenant"`
	Role          authzdomain.Role          `json:"role"`
	Administrator principaldomain.Principal `json:"administrator"`
	Grant         authzdomain.Grant         `json:"grant"`
	Created       bool                      `json:"created"`
}

// AdminBootstrap converges a deployment to one administrator: it creates the
// tenant, the administrator role, the administrator principal, and the grant
// only where each is missing. Re-running it is safe and appends no events
// once the deployment already matches, so an interrupted bootstrap can be
// retried without producing a second administrator.
//
// The command establishes no credential. Authentication factors arrive with
// the authentication slice; until then an administrator is an authorization
// subject only, which is why this is safe to expose without a secret.
func (s *Service) AdminBootstrap(
	ctx context.Context,
	tenantName string,
	identifier principaldomain.Identifier,
	actor string,
) (AdminBootstrapResult, error) {
	if actor == "" {
		return AdminBootstrapResult{}, errors.New("actor is required")
	}

	tenant, err := s.Bootstrap(ctx, tenantName, actor)
	if err != nil {
		return AdminBootstrapResult{}, err
	}
	result := AdminBootstrapResult{Tenant: tenant.Tenant, Created: tenant.Created}

	role, err := s.RoleGetByName(tenant.Tenant.ID, AdministratorRoleName)
	if errors.Is(err, ErrRoleNotFound) {
		role, err = s.RoleCreate(ctx, tenant.Tenant.ID, AdministratorRoleName, []authzdomain.Permission{
			{Action: "*", Resource: "*"},
		}, actor)
		result.Created = true
	}
	if err != nil {
		return AdminBootstrapResult{}, fmt.Errorf("administrator role: %w", err)
	}
	result.Role = role

	identifier.Value = principaldomain.NormalizeIdentifier(identifier.Value)
	administrator, err := s.PrincipalGetByIdentifier(tenant.Tenant.ID, identifier)
	if errors.Is(err, ErrPrincipalNotFound) {
		administrator, err = s.PrincipalCreate(
			ctx,
			tenant.Tenant.ID,
			principaldomain.KindHuman,
			identifier,
			actor,
		)
		result.Created = true
	}
	if err != nil {
		return AdminBootstrapResult{}, fmt.Errorf("administrator principal: %w", err)
	}
	result.Administrator = administrator

	grant, err := s.GrantCreate(ctx, tenant.Tenant.ID, administrator.ID, role.ID, actor)
	switch {
	case err == nil:
		result.Created = true
	case errors.Is(err, ErrGrantExists):
		grant, err = s.grantForSubject(tenant.Tenant.ID, administrator.ID, role.ID)
		if err != nil {
			return AdminBootstrapResult{}, err
		}
	default:
		return AdminBootstrapResult{}, fmt.Errorf("administrator grant: %w", err)
	}
	result.Grant = grant
	return result, nil
}

func (s *Service) grantForSubject(tenantID, subject, roleID string) (authzdomain.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, exists := s.grantKeys[identifierKey(tenantID, subject, roleID)]
	if !exists {
		return authzdomain.Grant{}, ErrGrantNotFound
	}
	return s.grants[id], nil
}
