package machine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"github.com/d31ma/sesame/internal/application/identity"
)

const (
	// StandardsContractVersion is versioned independently from the machine
	// protocol because host adapters and engine processes evolve on different
	// release schedules.
	StandardsContractVersion = "1"

	maxStandardsFields       = 64
	maxStandardsKeyBytes     = 128
	maxStandardsValueBytes   = 16 * 1024
	maxStandardsRequestBytes = 128 * 1024
)

// StandardsRequest is the framework-neutral boundary between a host's public
// HTTP route and SESAME's protocol implementation.
//
// Query and Form retain slices so duplicate parameters cannot be hidden by a
// framework's first-value accessor. Authorization and DPoP are the only HTTP
// headers the current endpoints consume; accepting an arbitrary header map
// would create a larger, less auditable trust boundary.
type StandardsRequest struct {
	ContractVersion string              `json:"contract_version"`
	Endpoint        string              `json:"endpoint"`
	Method          string              `json:"method"`
	Query           map[string][]string `json:"query,omitempty"`
	Form            map[string][]string `json:"form,omitempty"`
	Authorization   string              `json:"authorization,omitempty"`
	DPoP            string              `json:"dpop,omitempty"`
	HTTPURI         string              `json:"http_uri,omitempty"`
	Endpoints       *StandardsEndpoints `json:"endpoints,omitempty"`
}

// StandardsEndpoints are route paths owned by the host. They are used only
// for discovery; the engine resolves them against its configured issuer and
// refuses a path that escapes that origin.
type StandardsEndpoints struct {
	Authorization string `json:"authorization_endpoint,omitempty"`
	Token         string `json:"token_endpoint,omitempty"`
	JWKS          string `json:"jwks_uri,omitempty"`
	Introspection string `json:"introspection_endpoint,omitempty"`
	Revocation    string `json:"revocation_endpoint,omitempty"`
	EndSession    string `json:"end_session_endpoint,omitempty"`
}

// StandardsResponse is a bounded set of instructions a framework adapter can
// apply without understanding OAuth or OpenID Connect.
type StandardsResponse struct {
	ContractVersion string            `json:"contract_version"`
	Status          int               `json:"status"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            json.RawMessage   `json:"body,omitempty"`
	Action          *StandardsAction  `json:"action,omitempty"`
}

// StandardsAction describes a host-owned interaction that cannot be rendered
// by the headless engine. The interaction secret is bearer-equivalent and must
// stay in an encrypted server-side session or an HttpOnly, Secure cookie.
type StandardsAction struct {
	Kind              string   `json:"kind"`
	InteractionID     string   `json:"interaction_id"`
	InteractionSecret string   `json:"interaction_secret"`
	ClientID          string   `json:"client_id"`
	ClientName        string   `json:"client_name"`
	Scopes            []string `json:"scopes"`
	ExpiresAt         string   `json:"expires_at"`
}

// handleStandardsDispatch validates the public adapter envelope before any
// protocol handler sees it. A structurally invalid contract call is a machine
// error; a valid HTTP request that the protocol refuses is a StandardsResponse
// the host can serve.
func (p *Processor) handleStandardsDispatch(ctx context.Context, request Request) Response {
	var parameters StandardsRequest
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if parameters.ContractVersion != StandardsContractVersion {
		return errorResponse(request.RequestID, ErrorUnsupportedProtocol,
			"unsupported standards contract version")
	}
	if err := parameters.validate(); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}

	handler, found := p.standardsHandlers()[parameters.Endpoint]
	if !found {
		return errorResponse(request.RequestID, ErrorInvalidRequest,
			"endpoint is not part of the standards contract")
	}
	if parameters.Method != handler.method {
		return successResponse(request.RequestID, methodNotAllowed(handler.method))
	}
	return successResponse(request.RequestID, handler.dispatch(ctx, request.RequestID, parameters))
}

type standardsHandler struct {
	method   string
	dispatch func(context.Context, string, StandardsRequest) StandardsResponse
}

func (p *Processor) standardsHandlers() map[string]standardsHandler {
	return map[string]standardsHandler{
		"oidc.authorization": {
			method:   "GET",
			dispatch: p.dispatchAuthorizationEndpoint,
		},
		"oidc.discovery": {
			method:   "GET",
			dispatch: p.dispatchDiscoveryEndpoint,
		},
		"oidc.introspection": {
			method:   "POST",
			dispatch: p.dispatchIntrospectionEndpoint,
		},
		"oidc.jwks": {
			method:   "GET",
			dispatch: p.dispatchJWKSEndpoint,
		},
		"oidc.logout": {
			method:   "GET",
			dispatch: p.dispatchLogoutEndpoint,
		},
		"oidc.revocation": {
			method:   "POST",
			dispatch: p.dispatchRevocationEndpoint,
		},
		"oidc.token": {
			method:   "POST",
			dispatch: p.dispatchTokenEndpoint,
		},
	}
}

func (request StandardsRequest) validate() error {
	if request.Endpoint == "" || len(request.Endpoint) > maxStandardsKeyBytes {
		return errors.New("endpoint is required and must not exceed 128 bytes")
	}
	if request.Method == "" || request.Method != strings.ToUpper(request.Method) {
		return errors.New("method is required in uppercase")
	}
	if len(request.Authorization) > maxStandardsValueBytes ||
		len(request.DPoP) > maxStandardsValueBytes ||
		len(request.HTTPURI) > maxStandardsValueBytes {
		return errors.New("standards header or URI exceeds its maximum size")
	}
	if containsControl(request.Authorization) || containsControl(request.DPoP) ||
		containsControl(request.HTTPURI) {
		return errors.New("standards header or URI contains a control character")
	}

	total, err := validateStandardsValues(request.Query)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	formTotal, err := validateStandardsValues(request.Form)
	if err != nil {
		return fmt.Errorf("form: %w", err)
	}
	total += formTotal + len(request.Authorization) + len(request.DPoP) + len(request.HTTPURI)
	if total > maxStandardsRequestBytes {
		return errors.New("standards request exceeds its maximum size")
	}
	if request.Endpoints != nil {
		for _, endpoint := range []string{
			request.Endpoints.Authorization,
			request.Endpoints.Token,
			request.Endpoints.JWKS,
			request.Endpoints.Introspection,
			request.Endpoints.Revocation,
			request.Endpoints.EndSession,
		} {
			if len(endpoint) > maxStandardsValueBytes || containsControl(endpoint) {
				return errors.New("discovery endpoint is invalid")
			}
			total += len(endpoint)
		}
	}
	if total > maxStandardsRequestBytes {
		return errors.New("standards request exceeds its maximum size")
	}
	return nil
}

func validateStandardsValues(values map[string][]string) (int, error) {
	if len(values) > maxStandardsFields {
		return 0, errors.New("too many parameters")
	}
	total := 0
	entryCount := 0
	for key, entries := range values {
		if key == "" || len(key) > maxStandardsKeyBytes || containsControl(key) {
			return 0, errors.New("parameter name is invalid")
		}
		if len(entries) == 0 {
			return 0, fmt.Errorf("%s has no value", key)
		}
		entryCount += len(entries)
		if entryCount > maxStandardsFields {
			return 0, errors.New("too many parameter values")
		}
		total += len(key)
		for _, value := range entries {
			if len(value) > maxStandardsValueBytes || containsControl(value) {
				return 0, fmt.Errorf("%s has an invalid value", key)
			}
			total += len(value)
		}
	}
	return total, nil
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func (p *Processor) dispatchDiscoveryEndpoint(
	_ context.Context,
	requestID string,
	request StandardsRequest,
) StandardsResponse {
	if len(request.Query) != 0 || len(request.Form) != 0 ||
		request.Authorization != "" || request.DPoP != "" || request.HTTPURI != "" {
		return oauthError(400, "invalid_request", false)
	}
	parameters := StandardsEndpoints{}
	if request.Endpoints != nil {
		parameters = *request.Endpoints
	}
	response := p.handleDiscovery(machineRequest(requestID, parameters))
	return publicResult(response, 200, false)
}

func (p *Processor) dispatchJWKSEndpoint(
	_ context.Context,
	requestID string,
	request StandardsRequest,
) StandardsResponse {
	if !emptyStandardInput(request) {
		return oauthError(400, "invalid_request", false)
	}
	response := p.handleTokenJWKS(machineRequest(requestID, map[string]any{}))
	return publicResult(response, 200, false)
}

func (p *Processor) dispatchAuthorizationEndpoint(
	ctx context.Context,
	requestID string,
	request StandardsRequest,
) StandardsResponse {
	if len(request.Form) != 0 || request.Authorization != "" ||
		request.DPoP != "" || request.HTTPURI != "" || request.Endpoints != nil {
		return oauthError(400, "invalid_request", false)
	}
	if hasDuplicate(request.Query) {
		return oauthError(400, "invalid_request", false)
	}
	parameters := map[string]any{
		"client_id":             first(request.Query, "client_id"),
		"redirect_uri":          first(request.Query, "redirect_uri"),
		"response_type":         first(request.Query, "response_type"),
		"scopes":                strings.Fields(first(request.Query, "scope")),
		"state":                 first(request.Query, "state"),
		"nonce":                 first(request.Query, "nonce"),
		"code_challenge":        first(request.Query, "code_challenge"),
		"code_challenge_method": first(request.Query, "code_challenge_method"),
		"request_uri":           first(request.Query, "request_uri"),
	}
	response := p.handleAuthorize(ctx, machineRequest(requestID, parameters))
	if response.Error != nil {
		return oauthError(400, "invalid_request", true)
	}
	started, ok := response.Result.(identity.StartedInteraction)
	if !ok {
		return oauthError(503, "server_error", true)
	}
	return StandardsResponse{
		ContractVersion: StandardsContractVersion,
		Status:          200,
		Headers:         noStoreHeaders(),
		Action: &StandardsAction{
			Kind:              "interaction",
			InteractionID:     started.InteractionID,
			InteractionSecret: started.Secret,
			ClientID:          started.ClientID,
			ClientName:        started.ClientName,
			Scopes:            started.Scopes,
			ExpiresAt:         started.ExpiresAt,
		},
	}
}

func (p *Processor) dispatchTokenEndpoint(
	ctx context.Context,
	requestID string,
	request StandardsRequest,
) StandardsResponse {
	if len(request.Query) != 0 || request.Endpoints != nil || hasDuplicate(request.Form) {
		return oauthError(400, "invalid_request", true)
	}
	clientID, clientSecret, authentication := clientAuthentication(request)
	if authentication == clientAuthenticationInvalid {
		return invalidClient()
	}
	if authentication == clientAuthenticationMultiple {
		return oauthError(400, "invalid_request", true)
	}
	parameters := map[string]any{
		"grant_type":    first(request.Form, "grant_type"),
		"code":          first(request.Form, "code"),
		"redirect_uri":  first(request.Form, "redirect_uri"),
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code_verifier": first(request.Form, "code_verifier"),
		"refresh_token": first(request.Form, "refresh_token"),
		"device_code":   first(request.Form, "device_code"),
		"scope":         first(request.Form, "scope"),
		"dpop_proof":    request.DPoP,
		"http_method":   request.Method,
		"http_uri":      request.HTTPURI,
	}
	response := p.handleTokenExchange(ctx, machineRequest(requestID, parameters))
	if response.Error != nil {
		return tokenEndpointError(response.Error.Code)
	}
	return publicResult(response, 200, true)
}

func (p *Processor) dispatchIntrospectionEndpoint(
	_ context.Context,
	requestID string,
	request StandardsRequest,
) StandardsResponse {
	if len(request.Query) != 0 || request.Endpoints != nil ||
		request.DPoP != "" || request.HTTPURI != "" || hasDuplicate(request.Form) {
		return oauthError(400, "invalid_request", true)
	}
	clientID, clientSecret, authentication := clientAuthentication(request)
	if authentication == clientAuthenticationInvalid {
		return invalidClient()
	}
	if authentication == clientAuthenticationMultiple {
		return oauthError(400, "invalid_request", true)
	}
	response := p.handleIntrospect(machineRequest(requestID, map[string]any{
		"token":         first(request.Form, "token"),
		"client_id":     clientID,
		"client_secret": clientSecret,
	}))
	if response.Error != nil {
		return clientEndpointError(response.Error.Code)
	}
	return publicResult(response, 200, true)
}

func (p *Processor) dispatchRevocationEndpoint(
	ctx context.Context,
	requestID string,
	request StandardsRequest,
) StandardsResponse {
	if len(request.Query) != 0 || request.Endpoints != nil ||
		request.DPoP != "" || request.HTTPURI != "" || hasDuplicate(request.Form) {
		return oauthError(400, "invalid_request", true)
	}
	clientID, clientSecret, authentication := clientAuthentication(request)
	if authentication == clientAuthenticationInvalid {
		return invalidClient()
	}
	if authentication == clientAuthenticationMultiple {
		return oauthError(400, "invalid_request", true)
	}
	response := p.handleRevoke(ctx, machineRequest(requestID, map[string]any{
		"token":         first(request.Form, "token"),
		"client_id":     clientID,
		"client_secret": clientSecret,
	}))
	if response.Error != nil {
		return clientEndpointError(response.Error.Code)
	}
	return StandardsResponse{
		ContractVersion: StandardsContractVersion,
		Status:          200,
		Headers:         noStoreHeaders(),
	}
}

func (p *Processor) dispatchLogoutEndpoint(
	ctx context.Context,
	requestID string,
	request StandardsRequest,
) StandardsResponse {
	if len(request.Form) != 0 || request.Authorization != "" ||
		request.DPoP != "" || request.HTTPURI != "" ||
		request.Endpoints != nil || hasDuplicate(request.Query) {
		return oauthError(400, "invalid_request", true)
	}
	response := p.handleLogout(ctx, machineRequest(requestID, map[string]any{
		"id_token_hint":            first(request.Query, "id_token_hint"),
		"post_logout_redirect_uri": first(request.Query, "post_logout_redirect_uri"),
		"state":                    first(request.Query, "state"),
	}))
	if response.Error != nil {
		return oauthError(400, "invalid_request", true)
	}
	result, ok := response.Result.(identity.LogoutResult)
	if !ok {
		return oauthError(503, "server_error", true)
	}
	redirect, err := identity.LogoutRedirect(result)
	if err != nil {
		return oauthError(503, "server_error", true)
	}
	if redirect == "" {
		return jsonResponse(200, map[string]bool{"signed_out": true}, true)
	}
	return StandardsResponse{
		ContractVersion: StandardsContractVersion,
		Status:          303,
		Headers: map[string]string{
			"cache-control": "no-store",
			"location":      redirect,
		},
	}
}

type clientAuthenticationState uint8

const (
	clientAuthenticationValid clientAuthenticationState = iota
	clientAuthenticationInvalid
	clientAuthenticationMultiple
)

func clientAuthentication(request StandardsRequest) (string, string, clientAuthenticationState) {
	bodyID := first(request.Form, "client_id")
	bodySecret := first(request.Form, "client_secret")
	if request.Authorization == "" {
		return bodyID, bodySecret, clientAuthenticationValid
	}
	if bodySecret != "" {
		return "", "", clientAuthenticationMultiple
	}
	clientID, clientSecret, ok := parseBasicAuthorization(request.Authorization)
	if !ok {
		return "", "", clientAuthenticationInvalid
	}
	if bodyID != "" && bodyID != clientID {
		return "", "", clientAuthenticationMultiple
	}
	return clientID, clientSecret, clientAuthenticationValid
}

func parseBasicAuthorization(value string) (string, string, bool) {
	scheme, encoded, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, "Basic") || encoded == "" ||
		strings.Contains(encoded, " ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	clientID, clientSecret, found := strings.Cut(string(decoded), ":")
	if !found || clientID == "" {
		return "", "", false
	}
	clientID, err = url.QueryUnescape(clientID)
	if err != nil || clientID == "" {
		return "", "", false
	}
	clientSecret, err = url.QueryUnescape(clientSecret)
	if err != nil {
		return "", "", false
	}
	return clientID, clientSecret, true
}

func machineRequest(requestID string, parameters any) Request {
	encoded, err := json.Marshal(parameters)
	if err != nil {
		// All callers provide bounded, JSON-native structs and maps. Retaining
		// a malformed sentinel still makes an impossible encoding failure
		// fail closed in the strict downstream decoder.
		encoded = []byte("null")
	}
	return Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       requestID,
		Parameters:      encoded,
	}
}

func emptyStandardInput(request StandardsRequest) bool {
	return len(request.Query) == 0 &&
		len(request.Form) == 0 &&
		request.Authorization == "" &&
		request.DPoP == "" &&
		request.HTTPURI == "" &&
		request.Endpoints == nil
}

func hasDuplicate(values map[string][]string) bool {
	for _, entries := range values {
		if len(entries) != 1 {
			return true
		}
	}
	return false
}

func first(values map[string][]string, key string) string {
	entries := values[key]
	if len(entries) == 0 {
		return ""
	}
	return entries[0]
}

func publicResult(response Response, status int, noStore bool) StandardsResponse {
	if response.Error != nil {
		return oauthError(503, "server_error", noStore)
	}
	return jsonResponse(status, response.Result, noStore)
}

func jsonResponse(status int, value any, noStore bool) StandardsResponse {
	body, err := json.Marshal(value)
	if err != nil {
		return oauthError(503, "server_error", noStore)
	}
	headers := map[string]string{
		"content-type":           "application/json",
		"x-content-type-options": "nosniff",
	}
	if noStore {
		for name, value := range noStoreHeaders() {
			headers[name] = value
		}
	}
	return StandardsResponse{
		ContractVersion: StandardsContractVersion,
		Status:          status,
		Headers:         headers,
		Body:            body,
	}
}

func oauthError(status int, code string, noStore bool) StandardsResponse {
	return jsonResponse(status, struct {
		Error string `json:"error"`
	}{Error: code}, noStore)
}

func tokenEndpointError(code string) StandardsResponse {
	switch code {
	case ErrorClientNotFound, ErrorClientDisabled:
		return invalidClient()
	case ErrorInvalidGrant:
		return oauthError(400, "invalid_grant", true)
	case ErrorAuthorizationPending, ErrorSlowDown, ErrorAccessDenied:
		return oauthError(400, code, true)
	case ErrorDPoPProofInvalid, ErrorDPoPProofNotBound, ErrorDPoPProofExpired,
		ErrorDPoPProofReplayed, ErrorDPoPKeyMismatch, ErrorDPoPForeignOrigin,
		ErrorDPoPRequired:
		return oauthError(400, "invalid_dpop_proof", true)
	default:
		return oauthError(400, "invalid_request", true)
	}
}

func clientEndpointError(code string) StandardsResponse {
	switch code {
	case ErrorClientNotFound, ErrorClientDisabled, ErrorInvalidGrant:
		return invalidClient()
	default:
		return oauthError(400, "invalid_request", true)
	}
}

func invalidClient() StandardsResponse {
	response := oauthError(401, "invalid_client", true)
	response.Headers["www-authenticate"] = `Basic realm="sesame"`
	return response
}

func methodNotAllowed(allow string) StandardsResponse {
	response := oauthError(405, "invalid_request", true)
	response.Headers["allow"] = allow
	return response
}

func noStoreHeaders() map[string]string {
	return map[string]string{
		"cache-control": "no-store",
		"pragma":        "no-cache",
	}
}
