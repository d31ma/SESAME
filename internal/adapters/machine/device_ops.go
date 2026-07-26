package machine

import (
	"context"
	"errors"

	"github.com/d31ma/sesame/internal/application/identity"
)

// Stable error codes for the device authorization grant.
const (
	ErrorDeviceAuthorizationNotFound = "device_authorization_not_found"
	ErrorUserCodeNotFound            = "user_code_not_found"
	// ErrorAuthorizationPending and ErrorSlowDown are RFC 8628's own token
	// error codes, spelled exactly as the specification does, because a
	// device library will branch on those strings.
	ErrorAuthorizationPending = "authorization_pending"
	ErrorSlowDown             = "slow_down"
	ErrorAccessDenied         = "access_denied"

	// ErrorRequestURINotFound covers unknown, expired, spent, and
	// cross-client references alike.
	ErrorRequestURINotFound = "request_uri_not_found"
	// ErrorRequestURIConflict reports a request carrying both a reference and
	// loose parameters, which RFC 9126 forbids merging.
	ErrorRequestURIConflict = "request_uri_conflict"
)

// deviceRoutes are the operations this slice adds.
func (p *Processor) deviceRoutes() map[string]handlerFunc {
	return map[string]handlerFunc{
		"oidc.device_authorize": p.handleDeviceAuthorize,
		"oidc.device_lookup":    withoutContext(p.handleDeviceLookup),
		"oidc.device_approve":   p.handleDeviceApprove,
		"oidc.device_deny":      p.handleDeviceDeny,
		"oidc.pushed_authorize": p.handlePushedAuthorize,
	}
}

// handlePushedAuthorize is the back-channel half of RFC 9126: the client
// authenticates, the request is validated once, and what travels through the
// browser afterwards is an opaque reference nothing can edit.
func (p *Processor) handlePushedAuthorize(ctx context.Context, request Request) Response {
	if unavailable := p.requireDeviceStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		ClientID            string   `json:"client_id"`
		ClientSecret        string   `json:"client_secret"`
		RedirectURI         string   `json:"redirect_uri"`
		ResponseType        string   `json:"response_type"`
		Scopes              []string `json:"scopes"`
		State               string   `json:"state"`
		Nonce               string   `json:"nonce"`
		CodeChallenge       string   `json:"code_challenge"`
		CodeChallengeMethod string   `json:"code_challenge_method"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	pushed, err := p.tenant.PushedAuthorizationStart(ctx, identity.AuthorizationRequest{
		ClientID:            parameters.ClientID,
		RedirectURI:         parameters.RedirectURI,
		ResponseType:        parameters.ResponseType,
		Scopes:              parameters.Scopes,
		State:               parameters.State,
		Nonce:               parameters.Nonce,
		CodeChallenge:       parameters.CodeChallenge,
		CodeChallengeMethod: parameters.CodeChallengeMethod,
	}, parameters.ClientSecret, "operator:machine")
	if err != nil {
		return deviceErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, pushed)
}

func (p *Processor) requireDeviceStorage(request Request) *Response {
	if p.tenant == nil {
		response := errorResponse(request.RequestID, ErrorStorageNotConfigured,
			"device operations require a configured FYLO root")
		return &response
	}
	return nil
}

func (p *Processor) handleDeviceAuthorize(ctx context.Context, request Request) Response {
	if unavailable := p.requireDeviceStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		ClientID string   `json:"client_id"`
		Scopes   []string `json:"scopes"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	started, err := p.tenant.DeviceAuthorizationStart(ctx, parameters.ClientID,
		parameters.Scopes, "operator:machine")
	if err != nil {
		return deviceErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, started)
}

func (p *Processor) handleDeviceLookup(request Request) Response {
	if unavailable := p.requireDeviceStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		UserCode string `json:"user_code"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	pending, err := p.tenant.DeviceAuthorizationLookup(parameters.TenantID, parameters.UserCode)
	if err != nil {
		return deviceErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, pending)
}

func (p *Processor) handleDeviceApprove(ctx context.Context, request Request) Response {
	if unavailable := p.requireDeviceStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		UserCode string `json:"user_code"`
		// The session is proved, not named: this is the moment a person's
		// identity attaches to a device they are holding.
		SessionID     string `json:"session_id"`
		SessionSecret string `json:"session_secret"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	approved, err := p.tenant.DeviceAuthorizationApprove(ctx, parameters.TenantID,
		parameters.UserCode, parameters.SessionID, parameters.SessionSecret,
		"operator:machine")
	if err != nil {
		return deviceErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, approved)
}

func (p *Processor) handleDeviceDeny(ctx context.Context, request Request) Response {
	if unavailable := p.requireDeviceStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		UserCode string `json:"user_code"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.DeviceAuthorizationDeny(ctx, parameters.TenantID,
		parameters.UserCode, "operator:machine"); err != nil {
		return deviceErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]any{"denied": true})
}

// deviceErrorMap is the stable mapping from a domain error to a wire code.
//
// The three token-endpoint outcomes keep RFC 8628's own spelling: a device
// library branches on those strings, and inventing SESAME names for them
// would make every off-the-shelf client wrong.
var deviceErrorMap = []struct {
	sentinel error
	code     string
	message  string
}{
	{identity.ErrDeviceAuthorizationPending, ErrorAuthorizationPending,
		"the person has not approved this device yet"},
	{identity.ErrDeviceSlowDown, ErrorSlowDown,
		"poll no faster than the interval this authorization was issued with"},
	{identity.ErrDeviceAccessDenied, ErrorAccessDenied,
		"the device authorization was denied"},
	{identity.ErrDeviceAuthorizationNotFound, ErrorDeviceAuthorizationNotFound,
		"device authorization not found"},
	{identity.ErrUserCodeNotFound, ErrorUserCodeNotFound,
		"no pending device authorization for that user code"},
	{identity.ErrRequestURINotFound, ErrorRequestURINotFound,
		"request_uri not found"},
	{identity.ErrRequestURIConflict, ErrorRequestURIConflict,
		"a request_uri may not be combined with other authorization parameters"},
}

func deviceErrorResponse(requestID string, err error) Response {
	for _, mapping := range deviceErrorMap {
		if errors.Is(err, mapping.sentinel) {
			return errorResponse(requestID, mapping.code, mapping.message)
		}
	}
	return tenantErrorResponse(requestID, err)
}
