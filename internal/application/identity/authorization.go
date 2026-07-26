package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/d31ma/sesame/internal/domain/audit"
	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
)

// Stable authorization errors.
var (
	ErrRoleNotFound       = errors.New("role not found")
	ErrRoleExists         = errors.New("role name is already defined in this tenant")
	ErrGrantNotFound      = errors.New("grant not found")
	ErrGrantExists        = errors.New("this principal already holds this role")
	ErrStalePolicyVersion = errors.New("requested policy version is not current")
)

// Stable decision reason codes.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"

	ReasonAllowRoleGrant         = "allow_role_grant"
	ReasonAllowGroupGrant        = "allow_group_grant"
	ReasonDenyNoGrant            = "deny_no_grant"
	ReasonDenyPrincipalSuspended = "deny_principal_suspended"
	ReasonDenyPrincipalNotFound  = "deny_principal_not_found"
	ReasonDenyTenantNotFound     = "deny_tenant_not_found"
	ReasonDenyMissingContext     = "deny_missing_context"
	ReasonDenySessionInvalid     = "deny_session_invalid"

	// SessionContextPrefix names attributes the engine derives from a
	// verified session. A caller may not supply them: the whole point is
	// that assurance is proven rather than asserted.
	SessionContextPrefix = "session."
	// ContextAssurance is the derived attribute a permission uses to
	// require step-up, for example conditions {"session.assurance":"mfa"}.
	ContextAssurance = SessionContextPrefix + "assurance"

	maxDecisionBatch = 100
)

// DecisionRequest names one concrete authorization question.
type DecisionRequest struct {
	TenantID    string            `json:"tenant_id"`
	PrincipalID string            `json:"principal_id"`
	Action      string            `json:"action"`
	Resource    string            `json:"resource"`
	Context     map[string]string `json:"context,omitempty"`
	// SessionID and SessionSecret let the engine derive trusted context
	// rather than trusting the caller. When supplied, the session is
	// verified, its principal is used, and session.assurance is injected.
	SessionID     string `json:"session_id,omitempty"`
	SessionSecret string `json:"session_secret,omitempty"`
}

// Decision is one deterministic, auditable authorization answer. MissingKey
// names the context attribute a matching permission required but the request
// did not supply; it is set only with ReasonDenyMissingContext and is an
// attribute name, never a value.
type Decision struct {
	DecisionID    string `json:"decision_id"`
	Decision      string `json:"decision"`
	ReasonCode    string `json:"reason_code"`
	PolicyVersion int64  `json:"policy_version"`
	MissingKey    string `json:"missing_context_key,omitempty"`
}

// RoleCreate defines an immutable role. Role names are unique per tenant.
func (s *Service) RoleCreate(
	ctx context.Context,
	tenantID string,
	name string,
	permissions []authzdomain.Permission,
	actor string,
) (authzdomain.Role, error) {
	if err := s.requireLedger(); err != nil {
		return authzdomain.Role{}, err
	}
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return authzdomain.Role{}, err
	}
	normalized := tenantdomain.NormalizeName(name)
	if err := tenantdomain.ValidateName(normalized); err != nil {
		return authzdomain.Role{}, fmt.Errorf("role name: %w", err)
	}
	if err := authzdomain.ValidatePermissions(permissions); err != nil {
		return authzdomain.Role{}, err
	}
	if actor == "" {
		return authzdomain.Role{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[tenantID]; !exists {
		return authzdomain.Role{}, ErrNotFound
	}
	if _, exists := s.roleNames[identifierKey(tenantID, "role", normalized)]; exists {
		return authzdomain.Role{}, ErrRoleExists
	}

	id, err := authzdomain.NewRoleID()
	if err != nil {
		return authzdomain.Role{}, err
	}
	event, err := s.ledger.Append(ctx, authzdomain.EventRoleCreated, tenantID, actor, authzdomain.RoleCreatedPayload{
		RoleID:      id,
		TenantID:    tenantID,
		Name:        normalized,
		Permissions: authzdomain.EncodePermissions(permissions),
	})
	if err != nil {
		return authzdomain.Role{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyRoleCreated(event); err != nil {
		return authzdomain.Role{}, err
	}
	s.writeSnapshotLocked(ctx, id)
	return s.roles[id], nil
}

// RoleGetByName returns one role by normalized name inside a tenant.
func (s *Service) RoleGetByName(tenantID, name string) (authzdomain.Role, error) {
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return authzdomain.Role{}, err
	}
	normalized := tenantdomain.NormalizeName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	id, exists := s.roleNames[identifierKey(tenantID, "role", normalized)]
	if !exists {
		return authzdomain.Role{}, ErrRoleNotFound
	}
	return s.roles[id], nil
}

// GrantCreate assigns a role to a principal. Duplicate active assignments
// are rejected so revocation stays unambiguous.
func (s *Service) GrantCreate(
	ctx context.Context,
	tenantID string,
	principalID string,
	roleID string,
	actor string,
) (authzdomain.Grant, error) {
	if err := s.requireLedger(); err != nil {
		return authzdomain.Grant{}, err
	}
	if err := tenantdomain.ValidateID(tenantID); err != nil {
		return authzdomain.Grant{}, err
	}
	if err := principaldomain.ValidateID(principalID); err != nil {
		return authzdomain.Grant{}, err
	}
	if err := authzdomain.ValidateRoleID(roleID); err != nil {
		return authzdomain.Grant{}, err
	}
	if actor == "" {
		return authzdomain.Grant{}, errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[tenantID]; !exists {
		return authzdomain.Grant{}, ErrNotFound
	}
	principal, exists := s.principals[principalID]
	if !exists || principal.TenantID != tenantID {
		return authzdomain.Grant{}, ErrPrincipalNotFound
	}
	role, exists := s.roles[roleID]
	if !exists || role.TenantID != tenantID {
		return authzdomain.Grant{}, ErrRoleNotFound
	}
	if _, exists := s.grantKeys[identifierKey(tenantID, principalID, roleID)]; exists {
		return authzdomain.Grant{}, ErrGrantExists
	}

	id, err := authzdomain.NewGrantID()
	if err != nil {
		return authzdomain.Grant{}, err
	}
	event, err := s.ledger.Append(ctx, authzdomain.EventGrantCreated, tenantID, actor, authzdomain.GrantCreatedPayload{
		GrantID:     id,
		TenantID:    tenantID,
		PrincipalID: principalID,
		RoleID:      roleID,
	})
	if err != nil {
		return authzdomain.Grant{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyGrantCreated(event); err != nil {
		return authzdomain.Grant{}, err
	}
	s.writeSnapshotLocked(ctx, id)
	return s.grants[id], nil
}

// GrantRevoke durably removes a grant. Revoking an already revoked or
// unknown grant returns ErrGrantNotFound so privilege reduction is always
// explicit.
func (s *Service) GrantRevoke(ctx context.Context, grantID, actor string) error {
	if err := s.requireLedger(); err != nil {
		return err
	}
	if err := authzdomain.ValidateGrantID(grantID); err != nil {
		return err
	}
	if actor == "" {
		return errors.New("actor is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	grant, exists := s.grants[grantID]
	if !exists {
		return ErrGrantNotFound
	}
	event, err := s.ledger.Append(ctx, authzdomain.EventGrantRevoked, grant.TenantID, actor, authzdomain.GrantRevokedPayload{
		GrantID:  grantID,
		TenantID: grant.TenantID,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyGrantRevoked(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, grantID)
	return nil
}

// Decide answers one authorization question with default deny. A pinned
// policy version that is not current fails closed with
// ErrStalePolicyVersion instead of answering at a different version.
func (s *Service) Decide(request DecisionRequest, pinnedPolicyVersion *int64) (Decision, error) {
	decisions, err := s.DecideBatch([]DecisionRequest{request}, pinnedPolicyVersion)
	if err != nil {
		return Decision{}, err
	}
	return decisions[0], nil
}

// DecideBatch answers a bounded batch of authorization questions under one
// policy version so a batch can never mix versions.
func (s *Service) DecideBatch(
	requests []DecisionRequest,
	pinnedPolicyVersion *int64,
) ([]Decision, error) {
	if len(requests) == 0 {
		return nil, errors.New("at least one decision request is required")
	}
	if len(requests) > maxDecisionBatch {
		return nil, fmt.Errorf("a decision batch must not exceed %d requests", maxDecisionBatch)
	}
	for index, request := range requests {
		// A session proves both the tenant and the principal, so a
		// session-backed request need not repeat either; both are filled in
		// during evaluation from the verified session.
		if request.SessionID == "" {
			if err := tenantdomain.ValidateID(request.TenantID); err != nil {
				return nil, fmt.Errorf("request %d: %w", index, err)
			}
		} else if request.TenantID != "" {
			if err := tenantdomain.ValidateID(request.TenantID); err != nil {
				return nil, fmt.Errorf("request %d: %w", index, err)
			}
		}
		if request.SessionID == "" {
			if err := principaldomain.ValidateID(request.PrincipalID); err != nil {
				return nil, fmt.Errorf("request %d: %w", index, err)
			}
		} else if err := sessiondomain.ValidateID(request.SessionID); err != nil {
			return nil, fmt.Errorf("request %d: %w", index, err)
		}
		if err := authzdomain.ValidateValue(request.Action); err != nil {
			return nil, fmt.Errorf("request %d action: %w", index, err)
		}
		if err := authzdomain.ValidateValue(request.Resource); err != nil {
			return nil, fmt.Errorf("request %d resource: %w", index, err)
		}
		if err := authzdomain.ValidateContext(request.Context); err != nil {
			return nil, fmt.Errorf("request %d context: %w", index, err)
		}
		// Engine-derived attributes cannot be asserted by a caller; a
		// request that tries is rejected rather than silently overridden,
		// so a policy author can trust what the prefix means.
		for key := range request.Context {
			if strings.HasPrefix(key, SessionContextPrefix) {
				return nil, fmt.Errorf(
					"request %d context: %q is derived from a verified session and cannot be supplied",
					index, key,
				)
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if pinnedPolicyVersion != nil && *pinnedPolicyVersion != s.policyVersion {
		return nil, fmt.Errorf(
			"%w: requested %d, current %d",
			ErrStalePolicyVersion,
			*pinnedPolicyVersion,
			s.policyVersion,
		)
	}

	decisions := make([]Decision, 0, len(requests))
	for _, request := range requests {
		decision, err := s.decideLocked(request)
		if err != nil {
			return nil, err
		}
		decisions = append(decisions, decision)
	}
	return decisions, nil
}

func (s *Service) decideLocked(request DecisionRequest) (Decision, error) {
	decisionID, err := newDecisionID()
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{
		DecisionID:    decisionID,
		Decision:      DecisionDeny,
		PolicyVersion: s.policyVersion,
	}

	// A supplied session is verified here, and the attributes it proves are
	// derived rather than trusted. An unusable session denies outright: a
	// caller must not get an answer computed from a session it does not
	// actually hold.
	if request.SessionID != "" {
		session, exists := s.sessions[request.SessionID]
		if !exists ||
			!sessiondomain.VerifySecret(session.SecretDigest, request.SessionSecret) ||
			!session.Active(s.now()) ||
			s.principals[session.PrincipalID].Status != principaldomain.StatusActive {
			decision.ReasonCode = ReasonDenySessionInvalid
			return decision, nil
		}
		if request.PrincipalID != "" && request.PrincipalID != session.PrincipalID {
			decision.ReasonCode = ReasonDenySessionInvalid
			return decision, nil
		}
		if request.TenantID != "" && request.TenantID != session.TenantID {
			decision.ReasonCode = ReasonDenySessionInvalid
			return decision, nil
		}
		request.PrincipalID = session.PrincipalID
		request.TenantID = session.TenantID
		derived := make(map[string]string, len(request.Context)+1)
		for key, value := range request.Context {
			derived[key] = value
		}
		derived[ContextAssurance] = session.Assurance
		request.Context = derived
	}

	if _, exists := s.byID[request.TenantID]; !exists {
		decision.ReasonCode = ReasonDenyTenantNotFound
		return decision, nil
	}
	principal, exists := s.principals[request.PrincipalID]
	if !exists || principal.TenantID != request.TenantID {
		decision.ReasonCode = ReasonDenyPrincipalNotFound
		return decision, nil
	}
	if principal.Status != principaldomain.StatusActive {
		decision.ReasonCode = ReasonDenyPrincipalSuspended
		return decision, nil
	}

	// ponytail: linear grant scan; add a per-principal index when directory
	// sizes make this measurable.
	for _, grant := range s.grants {
		if grant.TenantID != request.TenantID {
			continue
		}
		reason := ""
		switch {
		case grant.PrincipalID == request.PrincipalID:
			reason = ReasonAllowRoleGrant
		case grant.GroupID != "":
			if _, isMember := s.memberships[grant.GroupID][request.PrincipalID]; isMember {
				reason = ReasonAllowGroupGrant
			}
		}
		if reason == "" {
			continue
		}
		role, exists := s.roles[grant.RoleID]
		if !exists {
			continue
		}
		for _, permission := range role.Permissions {
			if !authzdomain.Matches(permission.Action, request.Action) ||
				!authzdomain.Matches(permission.Resource, request.Resource) {
				continue
			}
			satisfied, missing := permission.ConditionsSatisfied(request.Context)
			if satisfied {
				decision.Decision = DecisionAllow
				decision.ReasonCode = reason
				return decision, nil
			}
			// Remember the first permission that matched the action and
			// resource but lacked a context attribute. An allow found later
			// still wins; only an otherwise-empty result reports it, so a
			// missing attribute never turns an allow into a deny.
			if missing != "" && decision.MissingKey == "" {
				decision.MissingKey = missing
			}
		}
	}
	if decision.MissingKey != "" {
		decision.ReasonCode = ReasonDenyMissingContext
		return decision, nil
	}
	decision.ReasonCode = ReasonDenyNoGrant
	return decision, nil
}

// PolicyVersion reports the current policy version: the ledger sequence of
// the latest policy-affecting event, immutable and replayable.
func (s *Service) PolicyVersion() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policyVersion
}

func (s *Service) applyRoleCreated(event audit.Event) error {
	var payload authzdomain.RoleCreatedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	permissions, err := authzdomain.DecodePermissions(payload.Permissions)
	if err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	role := authzdomain.Role{
		ID:          payload.RoleID,
		TenantID:    payload.TenantID,
		Name:        payload.Name,
		Permissions: permissions,
	}
	if err := s.admitRole(role); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	s.policyVersion = event.Sequence
	return nil
}

func (s *Service) applyGrantCreated(event audit.Event) error {
	var payload authzdomain.GrantCreatedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	grant := authzdomain.Grant{
		ID:          payload.GrantID,
		TenantID:    payload.TenantID,
		PrincipalID: payload.PrincipalID,
		GroupID:     payload.GroupID,
		RoleID:      payload.RoleID,
	}
	if err := s.admitGrant(grant); err != nil {
		return fmt.Errorf("event sequence %d: %w", event.Sequence, err)
	}
	s.policyVersion = event.Sequence
	return nil
}

func (s *Service) applyGrantRevoked(event audit.Event) error {
	var payload authzdomain.GrantRevokedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	grant, exists := s.grants[payload.GrantID]
	if !exists || grant.TenantID != payload.TenantID {
		return fmt.Errorf("event sequence %d revokes an unknown grant", event.Sequence)
	}
	subject := grant.PrincipalID
	if subject == "" {
		subject = grant.GroupID
	}
	delete(s.grants, payload.GrantID)
	delete(s.grantKeys, identifierKey(grant.TenantID, subject, grant.RoleID))
	s.policyVersion = event.Sequence
	return nil
}

func (s *Service) admitRole(role authzdomain.Role) error {
	if err := authzdomain.ValidateRoleID(role.ID); err != nil {
		return err
	}
	if err := tenantdomain.ValidateID(role.TenantID); err != nil {
		return err
	}
	if err := tenantdomain.ValidateName(role.Name); err != nil {
		return fmt.Errorf("role name: %w", err)
	}
	if err := authzdomain.ValidatePermissions(role.Permissions); err != nil {
		return err
	}
	if _, exists := s.byID[role.TenantID]; !exists {
		return fmt.Errorf("role %s belongs to unknown tenant", role.ID)
	}
	if _, exists := s.roles[role.ID]; exists {
		return errors.New("duplicate role ID")
	}
	nameKey := identifierKey(role.TenantID, "role", role.Name)
	if _, exists := s.roleNames[nameKey]; exists {
		return fmt.Errorf("role name %q is defined twice", role.Name)
	}
	s.roles[role.ID] = role
	s.roleNames[nameKey] = role.ID
	return nil
}

func (s *Service) admitGrant(grant authzdomain.Grant) error {
	if err := authzdomain.ValidateGrantID(grant.ID); err != nil {
		return err
	}
	subject := ""
	switch {
	case grant.PrincipalID != "" && grant.GroupID != "":
		return fmt.Errorf("grant %s names two subjects", grant.ID)
	case grant.PrincipalID != "":
		principal, exists := s.principals[grant.PrincipalID]
		if !exists || principal.TenantID != grant.TenantID {
			return fmt.Errorf("grant %s names an unknown principal", grant.ID)
		}
		subject = grant.PrincipalID
	case grant.GroupID != "":
		group, exists := s.groups[grant.GroupID]
		if !exists || group.TenantID != grant.TenantID {
			return fmt.Errorf("grant %s names an unknown group", grant.ID)
		}
		subject = grant.GroupID
	default:
		return fmt.Errorf("grant %s names no subject", grant.ID)
	}
	role, exists := s.roles[grant.RoleID]
	if !exists || role.TenantID != grant.TenantID {
		return fmt.Errorf("grant %s names an unknown role", grant.ID)
	}
	if _, exists := s.grants[grant.ID]; exists {
		return errors.New("duplicate grant ID")
	}
	claim := identifierKey(grant.TenantID, subject, grant.RoleID)
	if _, exists := s.grantKeys[claim]; exists {
		return errors.New("duplicate active grant for this subject and role")
	}
	s.grants[grant.ID] = grant
	s.grantKeys[claim] = grant.ID
	return nil
}

func newDecisionID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate decision ID: %w", err)
	}
	return "dec_" + hex.EncodeToString(value), nil
}
