package machine

import (
	"context"
	"errors"

	"github.com/d31ma/sesame/internal/application/identity"
	scimdomain "github.com/d31ma/sesame/internal/domain/scim"
)

// Stable error codes for SCIM 2.0 provisioning.
const (
	ErrorProvisioningDenied    = "provisioning_denied"
	ErrorProvisioningForbidden = "provisioning_forbidden"
	ErrorProvisioningClient    = "provisioning_client_not_found"
	ErrorSCIMUserNotFound      = "scim_user_not_found"
	ErrorSCIMGroupNotFound     = "scim_group_not_found"
	// ErrorSCIMConflict maps onto SCIM's 409, which providers reconcile
	// against. Collapsing it into a generic failure would leave a directory
	// retrying a create forever.
	ErrorSCIMConflict = "scim_user_conflict"
	// ErrorSCIMUnsupported covers a schema, PATCH operation, or filter
	// outside the subset SESAME implements. It is distinct from a malformed
	// request: the payload is well-formed, SESAME simply will not act on it.
	ErrorSCIMUnsupported = "scim_unsupported"
)

func (p *Processor) scimRoutes() map[string]handlerFunc {
	return map[string]handlerFunc{
		"scim.client_register":     p.handleSCIMClientRegister,
		"scim.client_disable":      p.handleSCIMClientDisable,
		"scim.client_rotate_token": p.handleSCIMClientRotateToken,
		"scim.user_create":         p.handleSCIMUserCreate,
		"scim.user_get":            withoutContext(p.handleSCIMUserGet),
		"scim.user_list":           withoutContext(p.handleSCIMUserList),
		"scim.user_patch":          p.handleSCIMUserPatch,
		"scim.user_deprovision":    p.handleSCIMUserDeprovision,
	}
}

// authenticateProvisioning resolves the bearer token every resource operation
// carries.
//
// The token is a parameter of each operation rather than a separate
// authenticate call, so the engine always authenticates and a host cannot
// forget to. It also keeps a SCIM request to one round trip.
func (p *Processor) authenticateProvisioning(
	request Request,
	token string,
) (scimdomain.Client, *Response) {
	if p.tenant == nil {
		response := errorResponse(request.RequestID, ErrorStorageNotConfigured,
			"provisioning requires a configured FYLO root")
		return scimdomain.Client{}, &response
	}
	client, err := p.tenant.ProvisioningAuthenticate(token)
	if err != nil {
		response := scimErrorResponse(request.RequestID, err)
		return scimdomain.Client{}, &response
	}
	return client, nil
}

func (p *Processor) handleSCIMClientRegister(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured,
			"provisioning requires a configured FYLO root")
	}
	var parameters struct {
		TenantID            string `json:"tenant_id"`
		Name                string `json:"name"`
		IdentifierNamespace string `json:"identifier_namespace"`
		CanManageGroups     bool   `json:"can_manage_groups"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	client, token, err := p.tenant.ProvisioningClientRegister(ctx, parameters.TenantID,
		parameters.Name, parameters.IdentifierNamespace, parameters.CanManageGroups,
		"operator:machine")
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	// The token is returned once. It is stored as a digest, so there is
	// nothing to return later even to an administrator.
	return successResponse(request.RequestID, map[string]any{
		"client": client,
		"token":  token,
	})
}

func (p *Processor) handleSCIMClientDisable(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured,
			"provisioning requires a configured FYLO root")
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		ClientID string `json:"scim_client_id"`
		Reason   string `json:"reason"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.ProvisioningClientDisable(ctx, parameters.TenantID,
		parameters.ClientID, parameters.Reason, "operator:machine"); err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]bool{"disabled": true})
}

// scimResourceRequest is the shape every resource operation shares.
type scimResourceRequest struct {
	Token      string `json:"token"`
	ResourceID string `json:"resource_id"`
	// Body is the SCIM payload as the host received it. It is parsed and
	// validated in the engine, never by the host.
	Body       string `json:"body"`
	Filter     string `json:"filter"`
	StartIndex int    `json:"start_index"`
	Count      int    `json:"count"`
}

func (p *Processor) handleSCIMUserCreate(ctx context.Context, request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	user, err := p.tenant.UserProvision(ctx, client, []byte(parameters.Body), "provisioning")
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, user)
}

func (p *Processor) handleSCIMUserGet(request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	user, err := p.tenant.UserGet(client, parameters.ResourceID)
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, user)
}

func (p *Processor) handleSCIMUserList(request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	list, err := p.tenant.UserList(client, parameters.Filter,
		parameters.StartIndex, parameters.Count)
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, list)
}

func (p *Processor) handleSCIMUserPatch(ctx context.Context, request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	user, err := p.tenant.UserPatch(ctx, client, parameters.ResourceID,
		[]byte(parameters.Body), "provisioning")
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, user)
}

func (p *Processor) handleSCIMUserDeprovision(ctx context.Context, request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	if err := p.tenant.UserDeprovision(ctx, client, parameters.ResourceID,
		"provisioning"); err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]bool{"deprovisioned": true})
}

// resourceRequest decodes and authenticates in one step, so no handler can do
// one without the other.
func (p *Processor) resourceRequest(
	request Request,
) (scimResourceRequest, scimdomain.Client, *Response) {
	var parameters scimResourceRequest
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		response := errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
		return parameters, scimdomain.Client{}, &response
	}
	client, failure := p.authenticateProvisioning(request, parameters.Token)
	return parameters, client, failure
}

// scimErrorMap is the stable mapping from a provisioning failure to a wire
// code.
var scimErrorMap = []struct {
	sentinel error
	code     string
	message  string
}{
	{identity.ErrProvisioningDenied, ErrorProvisioningDenied,
		"provisioning credentials were refused"},
	{identity.ErrProvisioningForbidden, ErrorProvisioningForbidden,
		"this provisioning client may not perform that operation"},
	{identity.ErrProvisioningClientNotFound, ErrorProvisioningClient,
		"provisioning client not found"},
	{identity.ErrSCIMUserNotFound, ErrorSCIMUserNotFound, "provisioned user not found"},
	{identity.ErrSCIMGroupNotFound, ErrorSCIMGroupNotFound, "provisioned group not found"},
	{identity.ErrSCIMUserConflict, ErrorSCIMConflict, "userName is already claimed"},
	{scimdomain.ErrUnsupportedSchema, ErrorSCIMUnsupported, ""},
	{scimdomain.ErrUnsupportedFilter, ErrorSCIMUnsupported, ""},
	{scimdomain.ErrImmutableField, ErrorSCIMUnsupported, ""},
}

// scimErrorResponse maps a provisioning failure onto the wire.
func scimErrorResponse(requestID string, err error) Response {
	for _, mapping := range scimErrorMap {
		if !errors.Is(err, mapping.sentinel) {
			continue
		}
		// An unsupported schema, filter, or field carries its own message:
		// the reason names the thing SESAME will not act on, which is what a
		// provider's operator needs to fix their configuration.
		if mapping.message == "" {
			return errorResponse(requestID, mapping.code, err.Error())
		}
		return errorResponse(requestID, mapping.code, mapping.message)
	}
	return tenantErrorResponse(requestID, err)
}

func (p *Processor) handleSCIMClientRotateToken(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured,
			"provisioning requires a configured FYLO root")
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		ClientID string `json:"scim_client_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	token, err := p.tenant.ProvisioningClientRotateToken(ctx, parameters.TenantID,
		parameters.ClientID, "operator:machine")
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	// Returned once, and the previous token stopped working the moment this
	// one was minted.
	return successResponse(request.RequestID, map[string]string{"token": token})
}

// scimGroupRoutes are the Group resource operations.
//
// They are gated by the provisioning client's CanManageGroups grant, checked
// in the service rather than here: group membership drives authorization
// decisions, so the gate belongs beside the state it protects.
func (p *Processor) scimGroupRoutes() map[string]handlerFunc {
	return map[string]handlerFunc{
		"scim.group_create":      p.handleSCIMGroupCreate,
		"scim.group_get":         withoutContext(p.handleSCIMGroupGet),
		"scim.group_list":        withoutContext(p.handleSCIMGroupList),
		"scim.group_patch":       p.handleSCIMGroupPatch,
		"scim.group_deprovision": p.handleSCIMGroupDeprovision,
	}
}

func (p *Processor) handleSCIMGroupCreate(ctx context.Context, request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	group, err := p.tenant.GroupProvision(ctx, client, []byte(parameters.Body), "provisioning")
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, group)
}

func (p *Processor) handleSCIMGroupGet(request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	group, err := p.tenant.GroupGet(client, parameters.ResourceID)
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, group)
}

func (p *Processor) handleSCIMGroupList(request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	list, err := p.tenant.GroupList(client, parameters.Filter,
		parameters.StartIndex, parameters.Count)
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, list)
}

func (p *Processor) handleSCIMGroupPatch(ctx context.Context, request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	group, err := p.tenant.GroupPatch(ctx, client, parameters.ResourceID,
		[]byte(parameters.Body), "provisioning")
	if err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, group)
}

func (p *Processor) handleSCIMGroupDeprovision(ctx context.Context, request Request) Response {
	parameters, client, failure := p.resourceRequest(request)
	if failure != nil {
		return *failure
	}
	if err := p.tenant.GroupDeprovision(ctx, client, parameters.ResourceID,
		"provisioning"); err != nil {
		return scimErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]bool{"deprovisioned": true})
}
