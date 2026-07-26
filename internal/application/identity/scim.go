package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	scimdomain "github.com/d31ma/sesame/internal/domain/scim"
)

// Stable provisioning errors.
var (
	// ErrProvisioningClientNotFound covers unknown, disabled, and
	// cross-tenant provisioning clients alike.
	ErrProvisioningClientNotFound = errors.New("provisioning client not found")
	// ErrProvisioningDenied reports a token that does not authenticate. It is
	// one error for an unknown client and a wrong token: telling them apart
	// would confirm which client identifiers exist.
	ErrProvisioningDenied = errors.New("provisioning credentials were refused")
	// ErrProvisioningForbidden reports an operation this client may not
	// perform, such as group management without that grant.
	ErrProvisioningForbidden = errors.New("this provisioning client may not perform that operation")
	// ErrSCIMUserNotFound reports an unknown provisioned user.
	ErrSCIMUserNotFound = errors.New("provisioned user not found")
	// ErrSCIMUserConflict reports a userName already claimed, which SCIM
	// requires be reported distinctly so a provider can reconcile.
	ErrSCIMUserConflict = errors.New("userName is already claimed")
)

// provisioningClient is a registered client and its token digest.
type provisioningClient struct {
	Client      scimdomain.Client
	TokenDigest string
}

// ProvisionedUser is a SCIM view of a principal.
type ProvisionedUser struct {
	ID          string `json:"id"`
	ExternalID  string `json:"externalId,omitempty"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName,omitempty"`
	Active      bool   `json:"active"`
}

// ProvisioningClientRegister records a system permitted to provision.
//
// The token is returned once and never again: it is stored as a digest, so
// there is nothing to return later even to an administrator.
func (s *Service) ProvisioningClientRegister(
	ctx context.Context,
	tenantID, name, namespace string,
	canManageGroups bool,
	actor string,
) (scimdomain.Client, string, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return scimdomain.Client{}, "", err
	}
	if err := scimdomain.ValidateName(name); err != nil {
		return scimdomain.Client{}, "", err
	}
	resolved, err := scimdomain.NormalizeIdentifierNamespace(namespace)
	if err != nil {
		return scimdomain.Client{}, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[tenantID]; !exists {
		return scimdomain.Client{}, "", ErrNotFound
	}
	return s.recordProvisioningClientLocked(ctx, tenantID, name, resolved, canManageGroups, actor)
}

func (s *Service) recordProvisioningClientLocked(
	ctx context.Context,
	tenantID, name, namespace string,
	canManageGroups bool,
	actor string,
) (scimdomain.Client, string, error) {
	clientID, err := scimdomain.NewClientID()
	if err != nil {
		return scimdomain.Client{}, "", err
	}
	token, digest, err := scimdomain.NewToken()
	if err != nil {
		return scimdomain.Client{}, "", err
	}
	event, err := s.ledger.Append(ctx, scimdomain.EventClientRegistered, tenantID, actor,
		scimdomain.ClientRegisteredPayload{
			ClientID:            clientID,
			TenantID:            tenantID,
			Name:                name,
			CanManageGroups:     canManageGroups,
			IdentifierNamespace: namespace,
			TokenDigest:         digest,
		})
	if err != nil {
		return scimdomain.Client{}, "", fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySCIMClientRegistered(event); err != nil {
		return scimdomain.Client{}, "", err
	}
	s.writeSnapshotLocked(ctx, clientID)
	return s.scimClients[clientID].Client, token, nil
}

// ProvisioningAuthenticate resolves a bearer token to its client.
//
// This is the gate on every provisioning request, so it is the one place that
// decides whether a caller may act at all.
func (s *Service) ProvisioningAuthenticate(token string) (scimdomain.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, stored := range s.scimClients {
		if stored.Client.Disabled {
			continue
		}
		if scimdomain.VerifyToken(token, stored.TokenDigest) {
			return stored.Client, nil
		}
	}
	return scimdomain.Client{}, ErrProvisioningDenied
}

// ProvisioningClientDisable durably stops a provisioning client.
func (s *Service) ProvisioningClientDisable(
	ctx context.Context,
	tenantID, clientID, reason, actor string,
) error {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return err
	}
	if err := scimdomain.ValidateClientID(clientID); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.scimClients[clientID]
	if !exists || stored.Client.TenantID != tenantID {
		return ErrProvisioningClientNotFound
	}
	if stored.Client.Disabled {
		return nil
	}
	return s.appendSCIMClientDisabled(ctx, tenantID, clientID, reason, actor)
}

func (s *Service) appendSCIMClientDisabled(
	ctx context.Context,
	tenantID, clientID, reason, actor string,
) error {
	event, err := s.ledger.Append(ctx, scimdomain.EventClientDisabled, tenantID, actor,
		scimdomain.ClientDisabledPayload{
			ClientID: clientID,
			TenantID: tenantID,
			Reason:   reason,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySCIMClientDisabled(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, clientID)
	return nil
}

// UserProvision creates or updates a principal from a SCIM User payload.
//
// SCIM's POST /Users is a create. A userName that is already claimed is a
// conflict, not an update: a provider that means to change someone sends PUT
// or PATCH against their id, and quietly merging a POST into an existing
// principal would let a provisioning client take over an account that already
// exists.
func (s *Service) UserProvision(
	ctx context.Context,
	client scimdomain.Client,
	document []byte,
	actor string,
) (ProvisionedUser, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return ProvisionedUser{}, err
	}
	user, err := scimdomain.ParseUser(document)
	if err != nil {
		return ProvisionedUser{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkProvisioningClientLocked(client); err != nil {
		return ProvisionedUser{}, err
	}
	key := identifierKey(client.TenantID, client.IdentifierNamespace,
		principaldomain.NormalizeIdentifier(user.UserName))
	if _, claimed := s.identifiers[key]; claimed {
		return ProvisionedUser{}, ErrSCIMUserConflict
	}
	return s.createProvisionedUserLocked(ctx, client, user, actor)
}

// checkProvisioningClientLocked re-reads the client from state, so a token
// authenticated a moment ago cannot act after the client was disabled.
func (s *Service) checkProvisioningClientLocked(client scimdomain.Client) error {
	stored, exists := s.scimClients[client.ID]
	if !exists || stored.Client.Disabled {
		return ErrProvisioningClientNotFound
	}
	return nil
}

func (s *Service) createProvisionedUserLocked(
	ctx context.Context,
	client scimdomain.Client,
	user scimdomain.User,
	actor string,
) (ProvisionedUser, error) {
	principalID, err := principaldomain.NewID()
	if err != nil {
		return ProvisionedUser{}, err
	}
	identifier := principaldomain.Identifier{
		Namespace: client.IdentifierNamespace,
		Value:     principaldomain.NormalizeIdentifier(user.UserName),
	}
	if err := principaldomain.ValidateIdentifier(identifier); err != nil {
		return ProvisionedUser{}, err
	}
	if err := s.appendPrincipalForProvisioning(ctx, client, principalID, identifier, actor); err != nil {
		return ProvisionedUser{}, err
	}
	if err := s.appendUserProvisioned(ctx, client, principalID, user, actor); err != nil {
		return ProvisionedUser{}, err
	}
	// A provider may create a user already deactivated, and a principal that
	// is active for even a moment is a window nobody asked for.
	if !user.IsActive() {
		if err := s.suspendForProvisioningLocked(ctx, principalID, client.TenantID, actor); err != nil {
			return ProvisionedUser{}, err
		}
	}
	s.writeSnapshotLocked(ctx, principalID)
	return s.provisionedViewLocked(principalID), nil
}

func (s *Service) appendPrincipalForProvisioning(
	ctx context.Context,
	client scimdomain.Client,
	principalID string,
	identifier principaldomain.Identifier,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, principaldomain.EventCreated, client.TenantID, actor,
		principaldomain.CreatedPayload{
			PrincipalID:         principalID,
			TenantID:            client.TenantID,
			Kind:                principaldomain.KindHuman,
			Status:              principaldomain.StatusActive,
			IdentifierNamespace: identifier.Namespace,
			IdentifierValue:     identifier.Value,
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applyPrincipalCreated(event)
}

func (s *Service) appendUserProvisioned(
	ctx context.Context,
	client scimdomain.Client,
	principalID string,
	user scimdomain.User,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, scimdomain.EventUserProvisioned, client.TenantID, actor,
		scimdomain.UserProvisionedPayload{
			PrincipalID: principalID,
			TenantID:    client.TenantID,
			ClientID:    client.ID,
			ExternalID:  user.ExternalID,
			UserName:    user.UserName,
			DisplayName: user.DisplayName,
			Active:      user.IsActive(),
			At:          s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applySCIMUserProvisioned(event)
}

// suspendForProvisioningLocked deactivates a principal through the same
// suspension path an administrator uses, so revocation behaves identically
// however it was triggered.
func (s *Service) suspendForProvisioningLocked(
	ctx context.Context,
	principalID, tenantID, actor string,
) error {
	event, err := s.ledger.Append(ctx, principaldomain.EventSuspended, tenantID, actor,
		principaldomain.SuspendedPayload{PrincipalID: principalID, TenantID: tenantID})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	return s.applyPrincipalSuspended(event)
}

// UserGet returns one provisioned user within its client's tenant.
func (s *Service) UserGet(client scimdomain.Client, principalID string) (ProvisionedUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkProvisioningClientLocked(client); err != nil {
		return ProvisionedUser{}, err
	}
	if err := s.checkProvisionedUserLocked(client, principalID); err != nil {
		return ProvisionedUser{}, err
	}
	return s.provisionedViewLocked(principalID), nil
}

// checkProvisionedUserLocked confirms a principal exists inside this client's
// tenant. Cross-tenant reads return "not found", never a denial that would
// confirm the principal exists somewhere.
func (s *Service) checkProvisionedUserLocked(
	client scimdomain.Client,
	principalID string,
) error {
	principal, exists := s.principals[principalID]
	if !exists || principal.TenantID != client.TenantID {
		return ErrSCIMUserNotFound
	}
	return nil
}

// UserList answers a filtered, paginated read.
type UserList struct {
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []ProvisionedUser `json:"Resources"`
}

// UserList returns the users a filter selects, bounded by pagination.
func (s *Service) UserList(
	client scimdomain.Client,
	filterExpression string,
	startIndex, count int,
) (UserList, error) {
	filter, filtered, err := scimdomain.ParseFilter(filterExpression)
	if err != nil {
		return UserList{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkProvisioningClientLocked(client); err != nil {
		return UserList{}, err
	}
	matched := s.matchProvisionedLocked(client, filter, filtered)
	page := scimdomain.ResolvePage(startIndex, count)
	return paginate(matched, page), nil
}

// matchProvisionedLocked selects this tenant's provisioned users.
func (s *Service) matchProvisionedLocked(
	client scimdomain.Client,
	filter scimdomain.Filter,
	filtered bool,
) []ProvisionedUser {
	matched := make([]ProvisionedUser, 0, len(s.scimUsers))
	for principalID, record := range s.scimUsers {
		if record.TenantID != client.TenantID {
			continue
		}
		if filtered && !matchesFilter(record, filter) {
			continue
		}
		matched = append(matched, s.provisionedViewLocked(principalID))
	}
	sort.Slice(matched, func(left, right int) bool {
		return matched[left].ID < matched[right].ID
	})
	return matched
}

func matchesFilter(record scimUser, filter scimdomain.Filter) bool {
	if filter.Attribute == "externalId" {
		return record.ExternalID == filter.Value
	}
	return record.UserName == filter.Value
}

// paginate applies SCIM's one-indexed window.
func paginate(matched []ProvisionedUser, page scimdomain.Page) UserList {
	total := len(matched)
	start := page.StartIndex - 1
	if start > total {
		start = total
	}
	end := start + page.Count
	if end > total {
		end = total
	}
	window := matched[start:end]
	return UserList{
		TotalResults: total,
		StartIndex:   page.StartIndex,
		ItemsPerPage: len(window),
		Resources:    window,
	}
}

// provisionedViewLocked renders a principal as SCIM sees it.
//
// Active is read from the principal's status rather than the SCIM record, so
// an administrator's suspension shows through to the provider instead of the
// two disagreeing silently.
func (s *Service) provisionedViewLocked(principalID string) ProvisionedUser {
	record := s.scimUsers[principalID]
	return ProvisionedUser{
		ID:          principalID,
		ExternalID:  record.ExternalID,
		UserName:    record.UserName,
		DisplayName: record.DisplayName,
		Active:      s.principals[principalID].Status == principaldomain.StatusActive,
	}
}

// UserDeprovision deactivates a provisioned user.
//
// SCIM's DELETE /Users/{id} is mapped to suspension, not erasure. Deleting
// the principal would delete the subject of every audit record it appears in,
// and an operator investigating what that account did would find a dangling
// identifier. Suspension is also what makes revocation durable: the same path
// an administrator uses, so sessions stop the same way.
//
// Deprovisioning twice is idempotent.
func (s *Service) UserDeprovision(
	ctx context.Context,
	client scimdomain.Client,
	principalID, actor string,
) error {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkProvisioningClientLocked(client); err != nil {
		return err
	}
	if err := s.checkProvisionedUserLocked(client, principalID); err != nil {
		return err
	}
	if s.principals[principalID].Status != principaldomain.StatusActive {
		return nil
	}
	return s.deprovisionLocked(ctx, client, principalID, actor)
}

func (s *Service) deprovisionLocked(
	ctx context.Context,
	client scimdomain.Client,
	principalID, actor string,
) error {
	if err := s.suspendForProvisioningLocked(ctx, principalID, client.TenantID, actor); err != nil {
		return err
	}
	event, err := s.ledger.Append(ctx, scimdomain.EventUserDeprovisioned, client.TenantID, actor,
		scimdomain.UserDeprovisionedPayload{
			PrincipalID: principalID,
			TenantID:    client.TenantID,
			ClientID:    client.ID,
			At:          s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySCIMUserDeprovisioned(event); err != nil {
		return err
	}
	s.writeSnapshotLocked(ctx, principalID)
	return nil
}

// UserPatch applies a bounded PATCH to a provisioned user.
//
// The whole request is validated before any part of it is applied. A PATCH
// that half-succeeds leaves identity state in a shape neither SESAME nor the
// provider believes in, and the provider's next reconcile would not know to
// fix it.
func (s *Service) UserPatch(
	ctx context.Context,
	client scimdomain.Client,
	principalID string,
	document []byte,
	actor string,
) (ProvisionedUser, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return ProvisionedUser{}, err
	}
	request, err := scimdomain.ParsePatch(document)
	if err != nil {
		return ProvisionedUser{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkProvisioningClientLocked(client); err != nil {
		return ProvisionedUser{}, err
	}
	if err := s.checkProvisionedUserLocked(client, principalID); err != nil {
		return ProvisionedUser{}, err
	}
	return s.resolvePatchLocked(ctx, client, principalID, request, actor)
}

// resolvePatchLocked resolves the whole request into a target state, then
// writes it.
//
// Not named apply*: in this package that prefix means "project a security
// event", and TestEveryProjectionIsReachableFromReplay enforces it by
// failing on any apply* method the replay table does not route.
func (s *Service) resolvePatchLocked(
	ctx context.Context,
	client scimdomain.Client,
	principalID string,
	request scimdomain.PatchRequest,
	actor string,
) (ProvisionedUser, error) {
	record := s.scimUsers[principalID]
	active := s.principals[principalID].Status == principaldomain.StatusActive
	for _, operation := range request.Operations {
		if err := foldReplace(&record, &active, operation); err != nil {
			return ProvisionedUser{}, err
		}
	}
	if err := s.writePatchLocked(ctx, client, principalID, record, active, actor); err != nil {
		return ProvisionedUser{}, err
	}
	s.writeSnapshotLocked(ctx, principalID)
	return s.provisionedViewLocked(principalID), nil
}

// foldReplace folds one operation into the target state.
func foldReplace(record *scimUser, active *bool, operation scimdomain.PatchOperation) error {
	switch normalizePath(operation.Path) {
	case "active":
		return json.Unmarshal(operation.Value, active)
	case "userName":
		return unmarshalString(operation.Value, &record.UserName, scimdomain.ValidateUserName)
	case "displayName":
		return unmarshalString(operation.Value, &record.DisplayName, nil)
	default:
		return unmarshalString(operation.Value, &record.ExternalID, nil)
	}
}

func normalizePath(path string) string {
	for _, candidate := range []string{"active", "userName", "displayName", "externalId"} {
		if strings.EqualFold(candidate, strings.TrimSpace(path)) {
			return candidate
		}
	}
	return "externalId"
}

func unmarshalString(raw json.RawMessage, target *string, validate func(string) error) error {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("the replacement value must be a string: %w", err)
	}
	if validate != nil {
		if err := validate(value); err != nil {
			return err
		}
	}
	*target = value
	return nil
}

// writePatchLocked appends the update, and the suspension or reinstatement
// the new active state implies.
func (s *Service) writePatchLocked(
	ctx context.Context,
	client scimdomain.Client,
	principalID string,
	record scimUser,
	active bool,
	actor string,
) error {
	event, err := s.ledger.Append(ctx, scimdomain.EventUserUpdated, client.TenantID, actor,
		scimdomain.UserUpdatedPayload{
			PrincipalID: principalID,
			TenantID:    client.TenantID,
			ClientID:    client.ID,
			ExternalID:  record.ExternalID,
			UserName:    record.UserName,
			DisplayName: record.DisplayName,
			At:          s.now().Format(time.RFC3339Nano),
		})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySCIMUserUpdated(event); err != nil {
		return err
	}
	return s.reconcileActiveLocked(ctx, client, principalID, active, actor)
}

// reconcileActiveLocked moves the principal to match the patched state.
//
// Reinstatement is deliberately not implemented: a provider setting
// active:true on a principal an administrator suspended would undo a human
// decision with a directory sync. Reactivation is an administrative action.
func (s *Service) reconcileActiveLocked(
	ctx context.Context,
	client scimdomain.Client,
	principalID string,
	active bool,
	actor string,
) error {
	currently := s.principals[principalID].Status == principaldomain.StatusActive
	if active || !currently {
		return nil
	}
	return s.deprovisionLocked(ctx, client, principalID, actor)
}

// ProvisioningClientRotateToken issues a fresh bearer token and invalidates
// the old one at the same moment.
//
// This is the remedy for a leaked token that does not also stop the
// directory: disabling the client would halt provisioning until someone
// reconfigures the provider, whereas rotation lets an operator cut off a
// leaked credential and hand the replacement over. The old token stops
// working immediately — there is no overlap window, because a window is
// exactly what an attacker holding the leaked token would use.
func (s *Service) ProvisioningClientRotateToken(
	ctx context.Context,
	tenantID, clientID, actor string,
) (string, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return "", err
	}
	if err := scimdomain.ValidateClientID(clientID); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, exists := s.scimClients[clientID]
	if !exists || stored.Client.TenantID != tenantID || stored.Client.Disabled {
		return "", ErrProvisioningClientNotFound
	}
	return s.rotateProvisioningTokenLocked(ctx, tenantID, clientID, actor)
}

func (s *Service) rotateProvisioningTokenLocked(
	ctx context.Context,
	tenantID, clientID, actor string,
) (string, error) {
	token, digest, err := scimdomain.NewToken()
	if err != nil {
		return "", err
	}
	event, err := s.ledger.Append(ctx, scimdomain.EventClientTokenRotated, tenantID, actor,
		scimdomain.ClientTokenRotatedPayload{
			ClientID:    clientID,
			TenantID:    tenantID,
			TokenDigest: digest,
		})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applySCIMClientTokenRotated(event); err != nil {
		return "", err
	}
	s.writeSnapshotLocked(ctx, clientID)
	return token, nil
}
