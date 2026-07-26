// Package machine implements SESAME's local, versioned NDJSON protocol.
package machine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	authzdomain "github.com/d31ma/sesame/internal/domain/authorization"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	domainprincipal "github.com/d31ma/sesame/internal/domain/principal"
	domaintenant "github.com/d31ma/sesame/internal/domain/tenant"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

const (
	// ProtocolVersion is the only machine protocol version supported by this
	// scaffold.
	ProtocolVersion = "1"
	// MaxFrameBytes bounds one request or response frame.
	MaxFrameBytes = 1 << 20

	// Stable machine error codes.
	ErrorFrameTooLarge        = "frame_too_large"
	ErrorInvalidJSON          = "invalid_json"
	ErrorInvalidRequest       = "invalid_request"
	ErrorUnsupportedProtocol  = "unsupported_protocol"
	ErrorOperationNotFound    = "operation_not_found"
	ErrorInternal             = "internal_error"
	ErrorStorageNotConfigured = "storage_not_configured"
	ErrorTenantNotFound       = "tenant_not_found"
	ErrorPrincipalNotFound    = "principal_not_found"
	ErrorIdentifierConflict   = "identifier_conflict"
	ErrorRoleNotFound         = "role_not_found"
	ErrorRoleExists           = "role_exists"
	ErrorGrantNotFound        = "grant_not_found"
	ErrorGrantExists          = "grant_exists"
	ErrorStalePolicyVersion   = "stale_policy_version"
	ErrorTransactionNotFound  = "transaction_not_found"
	ErrorTransactionClosed    = "transaction_closed"
	ErrorSessionNotFound      = "session_not_found"
	ErrorSessionInactive      = "session_inactive"
	ErrorTOTPNotEnrolled      = "totp_not_enrolled"
	ErrorTOTPAlreadyActive    = "totp_already_active"
	ErrorTOTPInvalidCode      = "totp_invalid_code"
	ErrorSecretsNotConfigured = "secrets_not_configured"
	ErrorSigningNotConfigured = "signing_not_configured"
	ErrorGroupNotFound        = "group_not_found"
	ErrorGroupExists          = "group_exists"
	ErrorGroupMemberExists    = "group_member_exists"
	ErrorGroupMemberNotFound  = "group_member_not_found"
	ErrorClientNotFound       = "client_not_found"
	ErrorClientExists         = "client_exists"
	ErrorClientDisabled       = "client_disabled"
	ErrorInteractionNotFound  = "interaction_not_found"
	ErrorInteractionClosed    = "interaction_closed"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorInvalidRedirectURI   = "invalid_redirect_uri"
	ErrorScopeNotAllowed      = "scope_not_allowed"
	ErrorIssuerNotConfigured  = "issuer_not_configured"
	ErrorRefreshFamilyMissing = "refresh_family_not_found"
	ErrorConsentRequired      = "consent_required"
	ErrorConsentNotFound      = "consent_not_found"
	ErrorPasskeyNotFound      = "passkey_not_found"
	ErrorPasskeyExists        = "passkey_exists"
	ErrorPasskeyChallenge     = "passkey_challenge_expired"
	ErrorPasskeyRejected      = "passkey_rejected"
	ErrorRelyingPartyMissing  = "relying_party_not_configured"
	ErrorInvalidLogoutHint    = "invalid_logout_hint"
	ErrorInvalidPostLogout    = "invalid_post_logout_redirect_uri"
)

var (
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	errFrameTooLarge = errors.New("machine frame exceeds maximum size")
)

// Request is one machine-protocol command.
type Request struct {
	ProtocolVersion string          `json:"protocol_version"`
	RequestID       string          `json:"request_id"`
	Operation       string          `json:"operation"`
	Parameters      json.RawMessage `json:"parameters"`
}

// Response is one machine-protocol result.
type Response struct {
	ProtocolVersion string         `json:"protocol_version"`
	RequestID       string         `json:"request_id"`
	OK              bool           `json:"ok"`
	Result          any            `json:"result,omitempty"`
	Error           *ProtocolError `json:"error,omitempty"`
}

// ProtocolError is safe for machine clients to inspect.
type ProtocolError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

// Processor handles local machine requests against application services.
// It reads and writes streams supplied by its owner and never opens a network
// listener.
type Processor struct {
	system  *system.Service
	tenant  *identity.Service
	metrics *processMetrics
	tracer  *slog.Logger
}

// New constructs a local machine protocol processor. A nil tenant service
// means storage is not configured; tenant operations then fail closed with a
// stable error instead of being absent.
func New(systemService *system.Service, tenantService *identity.Service) *Processor {
	return &Processor{
		system: systemService,
		tenant: tenantService,
		metrics: &processMetrics{
			startedAt: time.Now(),
			requests:  make(map[string]int64),
			errors:    make(map[string]int64),
		},
		tracer: slog.New(slog.DiscardHandler),
	}
}

// UseTracer emits one structured span record per completed request. Spans
// carry the caller's request_id so operators can correlate diagnostics with
// protocol traffic; they never contain parameters or results.
func (p *Processor) UseTracer(tracer *slog.Logger) {
	if tracer != nil {
		p.tracer = tracer
	}
}

type processMetrics struct {
	mu        sync.Mutex
	startedAt time.Time
	requests  map[string]int64
	errors    map[string]int64
}

// MetricsReport is the stable system.metrics result.
type MetricsReport struct {
	UptimeSeconds     float64          `json:"uptime_seconds"`
	Goroutines        int              `json:"goroutines"`
	HeapAllocBytes    uint64           `json:"heap_alloc_bytes"`
	StorageConfigured bool             `json:"storage_configured"`
	RequestsTotal     map[string]int64 `json:"requests_total"`
	ErrorsTotal       map[string]int64 `json:"errors_total"`
}

func (m *processMetrics) record(operation string, response Response) {
	if operation == "" {
		operation = "invalid"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[operation]++
	if response.Error != nil {
		m.errors[response.Error.Code]++
	}
}

func (m *processMetrics) report(storageConfigured bool) MetricsReport {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)

	m.mu.Lock()
	defer m.mu.Unlock()
	requests := make(map[string]int64, len(m.requests))
	for operation, count := range m.requests {
		requests[operation] = count
	}
	errors := make(map[string]int64, len(m.errors))
	for code, count := range m.errors {
		errors[code] = count
	}
	return MetricsReport{
		UptimeSeconds:     time.Since(m.startedAt).Seconds(),
		Goroutines:        runtime.NumGoroutine(),
		HeapAllocBytes:    memory.HeapAlloc,
		StorageConfigured: storageConfigured,
		RequestsTotal:     requests,
		ErrorsTotal:       errors,
	}
}

// Run processes one bounded JSON request per input line until EOF.
func (p *Processor) Run(ctx context.Context, input io.Reader, output io.Writer) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), MaxFrameBytes)
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		response := p.handle(ctx, bytes.TrimSpace(scanner.Bytes()))
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("encode machine response: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		response := errorResponse("", ErrorFrameTooLarge, "request frame exceeds the maximum size")
		if encodeErr := encoder.Encode(response); encodeErr != nil {
			return fmt.Errorf("encode oversized-frame response: %w", encodeErr)
		}
		return fmt.Errorf("%w: %v", errFrameTooLarge, err)
	}

	return nil
}

func (p *Processor) handle(ctx context.Context, frame []byte) Response {
	started := time.Now()
	response, operation := p.route(ctx, frame)
	p.metrics.record(operation, response)

	attributes := []any{
		"operation", operation,
		"request_id", response.RequestID,
		"ok", response.OK,
		"duration_ms", float64(time.Since(started).Microseconds()) / 1000,
	}
	if response.Error != nil {
		attributes = append(attributes, "error_code", response.Error.Code)
	}
	p.tracer.Info("machine request", attributes...)
	return response
}

func (p *Processor) route(ctx context.Context, frame []byte) (Response, string) {
	request, protocolError := decodeRequest(frame)
	if protocolError != nil {
		return errorResponse(request.RequestID, protocolError.Code, protocolError.Message), request.Operation
	}
	return p.dispatch(ctx, request), request.Operation
}

func (p *Processor) dispatch(ctx context.Context, request Request) Response {
	if request.ProtocolVersion != ProtocolVersion {
		return errorResponse(request.RequestID, ErrorUnsupportedProtocol, "unsupported protocol version")
	}
	if !requestIDPattern.MatchString(request.RequestID) {
		return errorResponse("", ErrorInvalidRequest, "request_id must match the documented format")
	}
	if request.Operation == "" || len(request.Operation) > 128 {
		return errorResponse(request.RequestID, ErrorInvalidRequest, "operation is required and must not exceed 128 bytes")
	}
	handler, known := p.routes()[request.Operation]
	if !known {
		return errorResponse(request.RequestID, ErrorOperationNotFound, "operation not found")
	}
	return handler(ctx, request)
}

// handlerFunc is one routed operation.
type handlerFunc func(context.Context, Request) Response

// routes is the operation table.
//
// A switch would work as well and was what this started as, but a 53-arm
// switch is one function of cyclomatic complexity 53 — indistinguishable, to
// any complexity budget, from 53 nested branches. A map is the same dispatch
// with none of that: each entry is data, and adding an operation no longer
// makes the routing function harder to reason about.
func (p *Processor) routes() map[string]handlerFunc {
	routed := map[string]handlerFunc{
		"system.ping":                           p.handlePing,
		"system.version":                        p.handleVersion,
		"system.readiness":                      p.handleReadiness,
		"system.metrics":                        p.handleMetrics,
		"tenant.bootstrap":                      p.handleTenantBootstrap,
		"tenant.get":                            func(_ context.Context, request Request) Response { return p.handleTenantGet(request) },
		"principal.create":                      p.handlePrincipalCreate,
		"principal.get":                         func(_ context.Context, request Request) Response { return p.handlePrincipalGet(request) },
		"principal.suspend":                     p.handlePrincipalSuspend,
		"role.create":                           p.handleRoleCreate,
		"grant.create":                          p.handleGrantCreate,
		"grant.revoke":                          p.handleGrantRevoke,
		"authorize.decide":                      func(_ context.Context, request Request) Response { return p.handleAuthorizeDecide(request) },
		"authorize.decide_batch":                func(_ context.Context, request Request) Response { return p.handleAuthorizeDecideBatch(request) },
		"group.create":                          p.handleGroupCreate,
		"group.member_add":                      func(ctx context.Context, request Request) Response { return p.handleGroupMember(ctx, request, true) },
		"group.member_remove":                   func(ctx context.Context, request Request) Response { return p.handleGroupMember(ctx, request, false) },
		"authenticator.set_password":            p.handleSetPassword,
		"authn.begin":                           p.handleAuthnBegin,
		"authenticator.totp_enroll":             p.handleTOTPEnroll,
		"authenticator.totp_activate":           p.handleTOTPActivate,
		"authenticator.recovery_codes_issue":    p.handleRecoveryIssue,
		"authenticator.passkey_register_begin":  func(_ context.Context, request Request) Response { return p.handlePasskeyRegisterBegin(request) },
		"authenticator.passkey_register_finish": p.handlePasskeyRegisterFinish,
		"authenticator.passkey_list":            func(_ context.Context, request Request) Response { return p.handlePasskeyList(request) },
		"authenticator.passkey_remove":          p.handlePasskeyRemove,
		"authn.passkey_options":                 func(_ context.Context, request Request) Response { return p.handlePasskeyOptions(request) },
		"authn.verify_passkey":                  p.handleAuthnVerifyPasskey,
		"authn.verify_recovery_code":            p.handleAuthnVerifyRecoveryCode,
		"authn.verify_totp":                     p.handleAuthnVerifyTOTP,
		"authn.verify_password":                 p.handleAuthnVerifyPassword,
		"authn.complete":                        p.handleAuthnComplete,
		"session.verify":                        func(_ context.Context, request Request) Response { return p.handleSessionVerify(request) },
		"session.revoke":                        p.handleSessionRevoke,
		"token.jwks":                            func(_ context.Context, request Request) Response { return p.handleTokenJWKS(request) },
		"oidc_client.register":                  p.handleClientRegister,
		"oidc_client.get":                       func(_ context.Context, request Request) Response { return p.handleClientGet(request) },
		"oidc_client.rotate_secret":             p.handleClientRotateSecret,
		"oidc_client.disable":                   p.handleClientDisable,
		"oidc.authorize":                        p.handleAuthorize,
		"oidc.interaction_complete":             p.handleInteractionComplete,
		"oidc.interaction_get":                  func(_ context.Context, request Request) Response { return p.handleInteractionGet(request) },
		"oidc.token":                            p.handleTokenExchange,
		"oidc.refresh_family_revoke":            p.handleRefreshFamilyRevoke,
		"oidc.refresh_family_get":               func(_ context.Context, request Request) Response { return p.handleRefreshFamilyGet(request) },
		"oidc.consent_grant":                    p.handleConsentGrant,
		"oidc.consent_withdraw":                 p.handleConsentWithdraw,
		"oidc.consent_get":                      func(_ context.Context, request Request) Response { return p.handleConsentGet(request) },
		"oidc.logout":                           p.handleLogout,
		"oidc.discovery":                        func(_ context.Context, request Request) Response { return p.handleDiscovery(request) },
		"oidc.introspect":                       func(_ context.Context, request Request) Response { return p.handleIntrospect(request) },
		"oidc.revoke":                           p.handleRevoke,
		"admin.bootstrap":                       p.handleAdminBootstrap,
	}
	for operation, handler := range p.federationRoutes() {
		routed[operation] = handler
	}
	for operation, handler := range p.scimRoutes() {
		routed[operation] = handler
	}
	for operation, handler := range p.scimGroupRoutes() {
		routed[operation] = handler
	}
	for operation, handler := range p.samlRoutes() {
		routed[operation] = handler
	}
	for operation, handler := range p.dpopRoutes() {
		routed[operation] = handler
	}
	for operation, handler := range p.deviceRoutes() {
		routed[operation] = handler
	}
	return routed
}

func (p *Processor) handleTenantBootstrap(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "tenant operations require a configured FYLO root")
	}
	var parameters struct {
		Name string `json:"name"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}

	result, err := p.tenant.Bootstrap(ctx, parameters.Name, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

func (p *Processor) handleTenantGet(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "tenant operations require a configured FYLO root")
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		Name     string `json:"name"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if (parameters.TenantID == "") == (parameters.Name == "") {
		return errorResponse(request.RequestID, ErrorInvalidRequest, "exactly one of tenant_id or name is required")
	}

	var (
		found domaintenant.Tenant
		err   error
	)
	if parameters.TenantID != "" {
		found, err = p.tenant.GetByID(parameters.TenantID)
	} else {
		found, err = p.tenant.GetByName(parameters.Name)
	}
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, found)
}

func (p *Processor) handlePrincipalCreate(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "principal operations require a configured FYLO root")
	}
	var parameters struct {
		TenantID            string `json:"tenant_id"`
		Kind                string `json:"kind"`
		IdentifierNamespace string `json:"identifier_namespace"`
		IdentifierValue     string `json:"identifier_value"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}

	created, err := p.tenant.PrincipalCreate(
		ctx,
		parameters.TenantID,
		parameters.Kind,
		domainprincipal.Identifier{
			Namespace: parameters.IdentifierNamespace,
			Value:     parameters.IdentifierValue,
		},
		"operator:machine",
	)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, created)
}

func (p *Processor) handlePrincipalGet(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "principal operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID         string `json:"principal_id"`
		TenantID            string `json:"tenant_id"`
		IdentifierNamespace string `json:"identifier_namespace"`
		IdentifierValue     string `json:"identifier_value"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}

	byID := parameters.PrincipalID != ""
	byIdentifier := parameters.TenantID != "" &&
		parameters.IdentifierNamespace != "" &&
		parameters.IdentifierValue != ""
	if byID == byIdentifier {
		return errorResponse(
			request.RequestID,
			ErrorInvalidRequest,
			"exactly one of principal_id or tenant_id with identifier_namespace and identifier_value is required",
		)
	}

	var (
		found domainprincipal.Principal
		err   error
	)
	if byID {
		found, err = p.tenant.PrincipalGetByID(parameters.PrincipalID)
	} else {
		found, err = p.tenant.PrincipalGetByIdentifier(parameters.TenantID, domainprincipal.Identifier{
			Namespace: parameters.IdentifierNamespace,
			Value:     parameters.IdentifierValue,
		})
	}
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, found)
}

func (p *Processor) handlePrincipalSuspend(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "principal operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID string `json:"principal_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}

	suspended, err := p.tenant.PrincipalSuspend(ctx, parameters.PrincipalID, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, suspended)
}

func (p *Processor) handleRoleCreate(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authorization operations require a configured FYLO root")
	}
	var parameters struct {
		TenantID    string                   `json:"tenant_id"`
		Name        string                   `json:"name"`
		Permissions []authzdomain.Permission `json:"permissions"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	created, err := p.tenant.RoleCreate(ctx, parameters.TenantID, parameters.Name, parameters.Permissions, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, created)
}

func (p *Processor) handleGrantCreate(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authorization operations require a configured FYLO root")
	}
	var parameters struct {
		TenantID    string `json:"tenant_id"`
		PrincipalID string `json:"principal_id"`
		GroupID     string `json:"group_id"`
		RoleID      string `json:"role_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if (parameters.PrincipalID == "") == (parameters.GroupID == "") {
		return errorResponse(request.RequestID, ErrorInvalidRequest, "exactly one of principal_id or group_id is required")
	}
	var (
		created authzdomain.Grant
		err     error
	)
	if parameters.PrincipalID != "" {
		created, err = p.tenant.GrantCreate(ctx, parameters.TenantID, parameters.PrincipalID, parameters.RoleID, "operator:machine")
	} else {
		created, err = p.tenant.GrantCreateForGroup(ctx, parameters.TenantID, parameters.GroupID, parameters.RoleID, "operator:machine")
	}
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, created)
}

func (p *Processor) handleGrantRevoke(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authorization operations require a configured FYLO root")
	}
	var parameters struct {
		GrantID string `json:"grant_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.GrantRevoke(ctx, parameters.GrantID, "operator:machine"); err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]any{"revoked": true})
}

func (p *Processor) handleAuthorizeDecide(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authorization operations require a configured FYLO root")
	}
	var parameters struct {
		identity.DecisionRequest
		PolicyVersion *int64 `json:"policy_version"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	decision, err := p.tenant.Decide(parameters.DecisionRequest, parameters.PolicyVersion)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, decision)
}

func (p *Processor) handleAuthorizeDecideBatch(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authorization operations require a configured FYLO root")
	}
	var parameters struct {
		Requests      []identity.DecisionRequest `json:"requests"`
		PolicyVersion *int64                     `json:"policy_version"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	decisions, err := p.tenant.DecideBatch(parameters.Requests, parameters.PolicyVersion)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]any{"decisions": decisions})
}

func (p *Processor) handleGroupCreate(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authorization operations require a configured FYLO root")
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		Name     string `json:"name"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	created, err := p.tenant.GroupCreate(ctx, parameters.TenantID, parameters.Name, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, created)
}

func (p *Processor) handleGroupMember(ctx context.Context, request Request, add bool) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authorization operations require a configured FYLO root")
	}
	var parameters struct {
		GroupID     string `json:"group_id"`
		PrincipalID string `json:"principal_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	var err error
	if add {
		err = p.tenant.GroupMemberAdd(ctx, parameters.GroupID, parameters.PrincipalID, "operator:machine")
	} else {
		err = p.tenant.GroupMemberRemove(ctx, parameters.GroupID, parameters.PrincipalID, "operator:machine")
	}
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]any{"member": add})
}

func (p *Processor) handleAdminBootstrap(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "administrator bootstrap requires a configured FYLO root")
	}
	var parameters struct {
		TenantName          string `json:"tenant_name"`
		IdentifierNamespace string `json:"identifier_namespace"`
		IdentifierValue     string `json:"identifier_value"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.AdminBootstrap(ctx, parameters.TenantName, domainprincipal.Identifier{
		Namespace: parameters.IdentifierNamespace,
		Value:     parameters.IdentifierValue,
	}, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

func (p *Processor) handleSetPassword(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID string `json:"principal_id"`
		Password    string `json:"password"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.PasswordSet(ctx, parameters.PrincipalID, parameters.Password, "operator:machine"); err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	// The response is deliberately empty: echoing anything derived from the
	// password would put it on a stream a caller might log.
	return successResponse(request.RequestID, map[string]any{"password_set": true})
}

func (p *Processor) handleAuthnBegin(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		TenantID            string `json:"tenant_id"`
		IdentifierNamespace string `json:"identifier_namespace"`
		IdentifierValue     string `json:"identifier_value"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.AuthenticationBegin(ctx, parameters.TenantID, domainprincipal.Identifier{
		Namespace: parameters.IdentifierNamespace,
		Value:     parameters.IdentifierValue,
	}, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

func (p *Processor) handleAuthnVerifyPassword(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		TransactionID string `json:"transaction_id"`
		Password      string `json:"password"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.AuthenticationVerifyPassword(
		ctx, parameters.TransactionID, parameters.Password, "operator:machine")
	if err != nil {
		// A closed transaction still returns its state so a client can show
		// why, but the operation is an error.
		response := tenantErrorResponse(request.RequestID, err)
		if response.Error != nil && response.Error.Code == ErrorTransactionClosed {
			response.Error.Details = map[string]any{
				"state":        result.State,
				"failure_code": result.FailureCode,
			}
		}
		return response
	}
	return successResponse(request.RequestID, result)
}

func (p *Processor) handleAuthnComplete(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		TransactionID   string `json:"transaction_id"`
		LifetimeSeconds int64  `json:"lifetime_seconds"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	issued, err := p.tenant.AuthenticationComplete(
		ctx,
		parameters.TransactionID,
		time.Duration(parameters.LifetimeSeconds)*time.Second,
		"operator:machine",
	)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, issued)
}

func (p *Processor) handleSessionVerify(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		SessionID string `json:"session_id"`
		Secret    string `json:"session_secret"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	session, err := p.tenant.SessionVerify(parameters.SessionID, parameters.Secret)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	// The stored secret digest never leaves the engine.
	session.SecretDigest = ""
	return successResponse(request.RequestID, session)
}

func (p *Processor) handleSessionRevoke(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		SessionID string `json:"session_id"`
		Reason    string `json:"reason"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.SessionRevoke(ctx, parameters.SessionID, parameters.Reason, "operator:machine"); err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]any{"revoked": true})
}

func (p *Processor) handleTOTPEnroll(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID string `json:"principal_id"`
		Issuer      string `json:"issuer"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	enrollment, err := p.tenant.TOTPEnroll(ctx, parameters.PrincipalID, parameters.Issuer, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	// The secret and its URI cross the boundary exactly here, once.
	return successResponse(request.RequestID, enrollment)
}

func (p *Processor) handleTOTPActivate(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID string `json:"principal_id"`
		Code        string `json:"code"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.TOTPActivate(ctx, parameters.PrincipalID, parameters.Code, "operator:machine"); err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]any{"activated": true})
}

func (p *Processor) handleAuthnVerifyTOTP(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		TransactionID string `json:"transaction_id"`
		Code          string `json:"code"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.AuthenticationVerifyTOTP(
		ctx, parameters.TransactionID, parameters.Code, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

func (p *Processor) handleRecoveryIssue(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID string `json:"principal_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	set, err := p.tenant.RecoveryCodesIssue(ctx, parameters.PrincipalID, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	// The codes cross the boundary exactly here, once.
	return successResponse(request.RequestID, set)
}

func (p *Processor) handleAuthnVerifyRecoveryCode(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "authentication operations require a configured FYLO root")
	}
	var parameters struct {
		TransactionID string `json:"transaction_id"`
		Code          string `json:"code"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.AuthenticationVerifyRecoveryCode(
		ctx, parameters.TransactionID, parameters.Code, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

// handleTokenJWKS publishes the public half of the deployment signing key.
// The host serves this at its own JWKS endpoint.
func (p *Processor) handleTokenJWKS(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "token operations require a configured FYLO root")
	}
	if err := requireEmptyParameters(request.Parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	keys, err := p.tenant.SigningKeys()
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, keys)
}

func (p *Processor) handleClientRegister(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "client operations require a configured FYLO root")
	}
	var parameters struct {
		TenantID               string   `json:"tenant_id"`
		Name                   string   `json:"name"`
		ClientType             string   `json:"client_type"`
		RedirectURIs           []string `json:"redirect_uris"`
		Scopes                 []string `json:"scopes"`
		Audience               string   `json:"audience"`
		PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	// The secret in this result is the only copy that will ever exist.
	result, err := p.tenant.ClientRegister(ctx, parameters.TenantID, parameters.Name,
		parameters.ClientType, parameters.RedirectURIs, parameters.Scopes,
		parameters.Audience, parameters.PostLogoutRedirectURIs, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

func (p *Processor) handleClientGet(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "client operations require a configured FYLO root")
	}
	var parameters struct {
		ClientID string `json:"client_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	client, err := p.tenant.ClientGet(parameters.ClientID)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, client)
}

func (p *Processor) handleClientRotateSecret(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "client operations require a configured FYLO root")
	}
	var parameters struct {
		ClientID string `json:"client_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	secret, err := p.tenant.ClientRotateSecret(ctx, parameters.ClientID, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]string{"client_secret": secret})
}

func (p *Processor) handleClientDisable(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "client operations require a configured FYLO root")
	}
	var parameters struct {
		ClientID string `json:"client_id"`
		Reason   string `json:"reason"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.ClientDisable(ctx, parameters.ClientID, parameters.Reason, "operator:machine"); err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]bool{"disabled": true})
}

// handleAuthorize validates a browser authorization request. The host has not
// shown the user anything yet: everything wrong with the request is found
// here, before a login page exists to be phished through.
func (p *Processor) handleAuthorize(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		ClientID            string   `json:"client_id"`
		RedirectURI         string   `json:"redirect_uri"`
		ResponseType        string   `json:"response_type"`
		Scopes              []string `json:"scopes"`
		State               string   `json:"state"`
		Nonce               string   `json:"nonce"`
		CodeChallenge       string   `json:"code_challenge"`
		CodeChallengeMethod string   `json:"code_challenge_method"`
		// RequestURI references a request pushed on the back channel. When
		// present, every other parameter but client_id must be absent.
		RequestURI string `json:"request_uri"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.AuthorizationStart(ctx, identity.AuthorizationRequest{
		ClientID:            parameters.ClientID,
		RedirectURI:         parameters.RedirectURI,
		ResponseType:        parameters.ResponseType,
		Scopes:              parameters.Scopes,
		State:               parameters.State,
		Nonce:               parameters.Nonce,
		CodeChallenge:       parameters.CodeChallenge,
		CodeChallengeMethod: parameters.CodeChallengeMethod,
		RequestURI:          parameters.RequestURI,
	}, "operator:machine")
	if err != nil {
		return deviceErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

func (p *Processor) handleInteractionComplete(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		InteractionID     string `json:"interaction_id"`
		InteractionSecret string `json:"interaction_secret"`
		SessionID         string `json:"session_id"`
		SessionSecret     string `json:"session_secret"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.AuthorizationComplete(ctx, parameters.InteractionID, parameters.InteractionSecret,
		parameters.SessionID, parameters.SessionSecret, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

func (p *Processor) handleInteractionGet(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		InteractionID string `json:"interaction_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	interaction, err := p.tenant.InteractionGet(parameters.InteractionID)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, interaction)
}

func (p *Processor) handleTokenExchange(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		GrantType    string `json:"grant_type"`
		Code         string `json:"code"`
		RedirectURI  string `json:"redirect_uri"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		CodeVerifier string `json:"code_verifier"`
		RefreshToken string `json:"refresh_token"`
		// DeviceCode carries the polling device's own credential on the
		// device grant. It never travels through a browser.
		DeviceCode string `json:"device_code"`
		Scope      string `json:"scope"`
		// DPoPProof binds the issued tokens to a client key (RFC 9449).
		// HTTPMethod and HTTPURI are the host's assertion about the request
		// it served, which the engine cannot observe for itself.
		DPoPProof  string `json:"dpop_proof"`
		HTTPMethod string `json:"http_method"`
		HTTPURI    string `json:"http_uri"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.TokenExchange(ctx, identity.TokenRequest{
		GrantType:    parameters.GrantType,
		Code:         parameters.Code,
		RedirectURI:  parameters.RedirectURI,
		ClientID:     parameters.ClientID,
		ClientSecret: parameters.ClientSecret,
		CodeVerifier: parameters.CodeVerifier,
		RefreshToken: parameters.RefreshToken,
		DeviceCode:   parameters.DeviceCode,
		Scope:        parameters.Scope,
		DPoPProof:    parameters.DPoPProof,
		DPoPMethod:   parameters.HTTPMethod,
		DPoPURI:      parameters.HTTPURI,
	}, "operator:machine")
	if err != nil {
		// The device grant's three outcomes reach the wire through the token
		// endpoint, so they have to be mapped here as well as on the device
		// operations — otherwise a polling device gets invalid_request where
		// RFC 8628 says authorization_pending. DPoP failures are mapped for
		// the same reason: a client that cannot tell a replayed proof from a
		// malformed request cannot fix either.
		return dpopErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

// handleRefreshFamilyRevoke is the durable logout primitive: it stops a
// client minting further tokens from one authorization.
func (p *Processor) handleRefreshFamilyRevoke(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		FamilyID string `json:"family_id"`
		Reason   string `json:"reason"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.RefreshFamilyRevoke(ctx, parameters.FamilyID, parameters.Reason, "operator:machine"); err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]bool{"revoked": true})
}

func (p *Processor) handleRefreshFamilyGet(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		FamilyID string `json:"family_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	family, err := p.tenant.RefreshFamilyGet(parameters.FamilyID)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, family)
}

// handleConsentGrant records a principal agreeing that one client may hold
// one scope set. The session proves who is agreeing; a principal ID from the
// caller would prove nothing.
func (p *Processor) handleConsentGrant(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		SessionID     string   `json:"session_id"`
		SessionSecret string   `json:"session_secret"`
		ClientID      string   `json:"client_id"`
		Scopes        []string `json:"scopes"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	consent, err := p.tenant.ConsentGrant(ctx, parameters.SessionID, parameters.SessionSecret,
		parameters.ClientID, parameters.Scopes, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, consent)
}

func (p *Processor) handleConsentWithdraw(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID string `json:"principal_id"`
		ClientID    string `json:"client_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.ConsentWithdraw(ctx, parameters.PrincipalID, parameters.ClientID, "operator:machine"); err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]bool{"withdrawn": true})
}

func (p *Processor) handleConsentGet(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID string `json:"principal_id"`
		ClientID    string `json:"client_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	consent, err := p.tenant.ConsentGet(parameters.PrincipalID, parameters.ClientID)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, consent)
}

// handleLogout ends the session an ID token was issued against. Revoking that
// session also ends every refresh grant resting on it, so one call is a
// complete logout rather than a cosmetic one.
func (p *Processor) handleLogout(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		IDTokenHint           string `json:"id_token_hint"`
		PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`
		State                 string `json:"state"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.Logout(ctx, identity.LogoutRequest{
		IDTokenHint:           parameters.IDTokenHint,
		PostLogoutRedirectURI: parameters.PostLogoutRedirectURI,
		State:                 parameters.State,
	}, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

// handleDiscovery publishes the provider configuration. The host names its
// own route paths; the engine composes them under the configured issuer and
// refuses any that would leave that origin.
func (p *Processor) handleDiscovery(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
		IntrospectionEndpoint string `json:"introspection_endpoint"`
		RevocationEndpoint    string `json:"revocation_endpoint"`
		// RP-initiated logout is implemented and the domain has always
		// advertised it. This field was missing here, so a host that named its
		// logout route — as the SDK's own typed field invites — had the whole
		// call refused by the strict decoder, and no deployment could publish
		// end_session_endpoint at all.
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	metadata, err := p.tenant.Discovery(oidcdomain.Endpoints{
		Authorization: parameters.AuthorizationEndpoint,
		Token:         parameters.TokenEndpoint,
		JWKS:          parameters.JWKSURI,
		Introspection: parameters.IntrospectionEndpoint,
		Revocation:    parameters.RevocationEndpoint,
		EndSession:    parameters.EndSessionEndpoint,
	})
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, metadata)
}

// handleIntrospect answers whether a token is currently usable. An inactive
// answer carries nothing but the flag, so the endpoint is not an oracle.
func (p *Processor) handleIntrospect(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		Token        string `json:"token"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.Introspect(identity.TokenRequest{
		ClientID:     parameters.ClientID,
		ClientSecret: parameters.ClientSecret,
	}, parameters.Token)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

// handleRevoke acknowledges every well-formed request from an authenticated
// client, whether or not there was anything to revoke. RFC 7009 section 2.2
// requires that: an endpoint that distinguished them would confirm token
// guesses.
func (p *Processor) handleRevoke(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		Token        string `json:"token"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.Revoke(ctx, identity.TokenRequest{
		ClientID:     parameters.ClientID,
		ClientSecret: parameters.ClientSecret,
	}, parameters.Token, "operator:machine"); err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]bool{"acknowledged": true})
}

// decodeBase64 reads one base64url or standard-base64 field. WebAuthn values
// arrive from browsers that differ on padding and alphabet, and rejecting a
// conforming client over that would be a interoperability bug rather than a
// security property — the values are verified cryptographically afterwards.
func decodeBase64(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("value is not base64")
}

func (p *Processor) handlePasskeyRegisterBegin(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "passkey operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID string `json:"principal_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.PasskeyRegisterBegin(parameters.PrincipalID)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

func (p *Processor) handlePasskeyRegisterFinish(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "passkey operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID       string `json:"principal_id"`
		AttestationObject string `json:"attestation_object"`
		ClientDataJSON    string `json:"client_data_json"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	attestation, err := decodeBase64(parameters.AttestationObject)
	if err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, "attestation_object must be base64")
	}
	clientData, err := decodeBase64(parameters.ClientDataJSON)
	if err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, "client_data_json must be base64")
	}
	stored, err := p.tenant.PasskeyRegisterFinish(ctx, parameters.PrincipalID, attestation, clientData, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, stored)
}

func (p *Processor) handlePasskeyList(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "passkey operations require a configured FYLO root")
	}
	var parameters struct {
		PrincipalID string `json:"principal_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	passkeys, err := p.tenant.PasskeyList(parameters.PrincipalID)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]any{"passkeys": passkeys})
}

func (p *Processor) handlePasskeyRemove(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "passkey operations require a configured FYLO root")
	}
	var parameters struct {
		CredentialID string `json:"credential_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.PasskeyRemove(ctx, parameters.CredentialID, "operator:machine"); err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]bool{"removed": true})
}

func (p *Processor) handlePasskeyOptions(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "passkey operations require a configured FYLO root")
	}
	var parameters struct {
		TransactionID string `json:"transaction_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	options, err := p.tenant.PasskeyAuthenticationOptions(parameters.TransactionID)
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, options)
}

func (p *Processor) handleAuthnVerifyPasskey(ctx context.Context, request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "passkey operations require a configured FYLO root")
	}
	var parameters struct {
		TransactionID     string `json:"transaction_id"`
		CredentialID      string `json:"credential_id"`
		AuthenticatorData string `json:"authenticator_data"`
		ClientDataJSON    string `json:"client_data_json"`
		Signature         string `json:"signature"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	authData, err := decodeBase64(parameters.AuthenticatorData)
	if err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, "authenticator_data must be base64")
	}
	clientData, err := decodeBase64(parameters.ClientDataJSON)
	if err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, "client_data_json must be base64")
	}
	signature, err := decodeBase64(parameters.Signature)
	if err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, "signature must be base64")
	}
	result, err := p.tenant.AuthenticationVerifyPasskey(ctx, parameters.TransactionID,
		parameters.CredentialID, authData, clientData, signature, "operator:machine")
	if err != nil {
		return tenantErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

func tenantErrorResponse(requestID string, err error) Response {
	if errors.Is(err, identity.ErrInvalidLogoutHint) {
		return errorResponse(requestID, ErrorInvalidLogoutHint,
			"id_token_hint is not a token this deployment issued")
	}
	if errors.Is(err, identity.ErrInvalidPostLogoutRedirect) {
		return errorResponse(requestID, ErrorInvalidPostLogout,
			"post-logout redirect URI is not registered for this client")
	}
	if errors.Is(err, identity.ErrPasskeyNotFound) {
		return errorResponse(requestID, ErrorPasskeyNotFound, "passkey not found")
	}
	if errors.Is(err, identity.ErrPasskeyExists) {
		return errorResponse(requestID, ErrorPasskeyExists, "this credential is already registered")
	}
	if errors.Is(err, identity.ErrPasskeyChallengeExpired) {
		return errorResponse(requestID, ErrorPasskeyChallenge,
			"the registration challenge has expired; begin again")
	}
	if errors.Is(err, identity.ErrNoRelyingParty) {
		return errorResponse(requestID, ErrorRelyingPartyMissing,
			"a passkey is bound to a domain and requires an issuer in the deployment configuration")
	}
	// Every way an attestation can be wrong is one code. Which check failed
	// is diagnostic detail an attacker does not need.
	for _, rejection := range []error{
		authenticatordomain.ErrPasskeyUnsupportedAttestation,
		authenticatordomain.ErrPasskeyUnsupportedAlgorithm,
		authenticatordomain.ErrPasskeyInvalidClientData,
		authenticatordomain.ErrPasskeyInvalidAuthData,
		authenticatordomain.ErrPasskeyInvalidSignature,
		authenticatordomain.ErrPasskeyCloned,
	} {
		if errors.Is(err, rejection) {
			return errorResponse(requestID, ErrorPasskeyRejected, "passkey registration was rejected")
		}
	}
	// invalid_grant is deliberately one code for every way a code can fail:
	// wrong client, wrong redirect, wrong verifier, expired, or already
	// spent. Distinguishing them would tell an attacker which half of a
	// guess was right.
	if errors.Is(err, identity.ErrInvalidGrant) {
		return errorResponse(requestID, ErrorInvalidGrant, "authorization grant is not valid")
	}
	// consent_required is not a failure: the host is expected to show a
	// consent screen and come back, so it must be distinguishable from every
	// other reason an interaction cannot complete.
	if errors.Is(err, identity.ErrConsentRequired) {
		return errorResponse(requestID, ErrorConsentRequired,
			"this client requires the principal's consent for the requested scopes")
	}
	if errors.Is(err, identity.ErrConsentNotFound) {
		return errorResponse(requestID, ErrorConsentNotFound, "consent not found")
	}
	if errors.Is(err, identity.ErrRefreshFamilyNotFound) {
		return errorResponse(requestID, ErrorRefreshFamilyMissing, "refresh token family not found")
	}
	if errors.Is(err, identity.ErrInteractionNotFound) {
		return errorResponse(requestID, ErrorInteractionNotFound, "interaction not found")
	}
	if errors.Is(err, identity.ErrInteractionClosed) {
		return errorResponse(requestID, ErrorInteractionClosed, "interaction accepts no further steps")
	}
	if errors.Is(err, identity.ErrInvalidRedirectURI) {
		return errorResponse(requestID, ErrorInvalidRedirectURI, "redirect URI is not registered for this client")
	}
	if errors.Is(err, identity.ErrScopeNotAllowed) {
		return errorResponse(requestID, ErrorScopeNotAllowed, err.Error())
	}
	if errors.Is(err, identity.ErrNoIssuer) {
		return errorResponse(requestID, ErrorIssuerNotConfigured,
			"this operation mints tokens and requires an issuer in the deployment configuration")
	}
	if errors.Is(err, identity.ErrClientNotFound) {
		return errorResponse(requestID, ErrorClientNotFound, "oidc client not found")
	}
	if errors.Is(err, identity.ErrClientExists) {
		return errorResponse(requestID, ErrorClientExists, "oidc client name is already defined in this tenant")
	}
	if errors.Is(err, identity.ErrClientDisabled) {
		return errorResponse(requestID, ErrorClientDisabled, "oidc client is disabled")
	}
	if errors.Is(err, tokendomain.ErrNoSigningKey) {
		return errorResponse(requestID, ErrorSigningNotConfigured,
			"this operation signs or publishes tokens and requires a deployment key")
	}
	if errors.Is(err, identity.ErrTOTPNotEnrolled) {
		return errorResponse(requestID, ErrorTOTPNotEnrolled, "principal has no TOTP authenticator")
	}
	if errors.Is(err, identity.ErrTOTPAlreadyActive) {
		return errorResponse(requestID, ErrorTOTPAlreadyActive, "principal already has an active TOTP authenticator")
	}
	if errors.Is(err, identity.ErrTOTPInvalidCode) {
		return errorResponse(requestID, ErrorTOTPInvalidCode, "TOTP code is not valid")
	}
	if errors.Is(err, authenticatordomain.ErrNoSealingKey) {
		return errorResponse(requestID, ErrorSecretsNotConfigured,
			"this operation stores a recoverable secret and requires a deployment key")
	}
	if errors.Is(err, identity.ErrGroupNotFound) {
		return errorResponse(requestID, ErrorGroupNotFound, "group not found")
	}
	if errors.Is(err, identity.ErrGroupExists) {
		return errorResponse(requestID, ErrorGroupExists, "group name is already defined in this tenant")
	}
	if errors.Is(err, identity.ErrGroupMemberExists) {
		return errorResponse(requestID, ErrorGroupMemberExists, "principal is already a member of this group")
	}
	if errors.Is(err, identity.ErrGroupMemberNotFound) {
		return errorResponse(requestID, ErrorGroupMemberNotFound, "principal is not a member of this group")
	}
	if errors.Is(err, identity.ErrNotFound) {
		return errorResponse(requestID, ErrorTenantNotFound, "tenant not found")
	}
	if errors.Is(err, identity.ErrRoleNotFound) {
		return errorResponse(requestID, ErrorRoleNotFound, "role not found")
	}
	if errors.Is(err, identity.ErrRoleExists) {
		return errorResponse(requestID, ErrorRoleExists, "role name is already defined in this tenant")
	}
	if errors.Is(err, identity.ErrGrantNotFound) {
		return errorResponse(requestID, ErrorGrantNotFound, "grant not found")
	}
	if errors.Is(err, identity.ErrGrantExists) {
		return errorResponse(requestID, ErrorGrantExists, "this principal already holds this role")
	}
	if errors.Is(err, identity.ErrTransactionNotFound) {
		return errorResponse(requestID, ErrorTransactionNotFound, "authentication transaction not found")
	}
	if errors.Is(err, identity.ErrTransactionClosed) {
		return errorResponse(requestID, ErrorTransactionClosed, "authentication transaction accepts no further attempts")
	}
	// A wrong secret and an unknown session are one code on purpose: telling
	// them apart would confirm that a session ID exists.
	if errors.Is(err, identity.ErrSessionNotFound) {
		return errorResponse(requestID, ErrorSessionNotFound, "session not found")
	}
	if errors.Is(err, identity.ErrSessionInactive) {
		return errorResponse(requestID, ErrorSessionInactive, "session is expired or revoked")
	}
	if errors.Is(err, identity.ErrStalePolicyVersion) {
		return errorResponse(requestID, ErrorStalePolicyVersion, "requested policy version is not current")
	}
	if errors.Is(err, identity.ErrPrincipalNotFound) {
		return errorResponse(requestID, ErrorPrincipalNotFound, "principal not found")
	}
	if errors.Is(err, identity.ErrIdentifierConflict) {
		return errorResponse(requestID, ErrorIdentifierConflict, "identifier is already claimed in this tenant and namespace")
	}
	if errors.Is(err, identity.ErrStorageFailure) {
		response := errorResponse(requestID, ErrorInternal, "security ledger operation failed")
		response.Error.Retryable = true
		return response
	}
	return errorResponse(requestID, ErrorInvalidRequest, err.Error())
}

func decodeParameters(parameters json.RawMessage, target any) error {
	if len(parameters) == 0 {
		return errors.New("parameters must be a JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(parameters))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("parameters do not match the operation schema")
	}
	return nil
}

func decodeRequest(frame []byte) (Request, *ProtocolError) {
	var request Request
	if len(frame) == 0 || !json.Valid(frame) {
		return request, &ProtocolError{
			Code:      ErrorInvalidJSON,
			Message:   "request must be one valid JSON object",
			Retryable: false,
		}
	}
	if err := rejectDuplicateKeys(frame); err != nil {
		return request, &ProtocolError{
			Code:      ErrorInvalidRequest,
			Message:   "request contains duplicate object fields",
			Retryable: false,
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, &ProtocolError{
			Code:      ErrorInvalidRequest,
			Message:   "request does not match the machine protocol schema",
			Retryable: false,
		}
	}

	return request, nil
}

func rejectDuplicateKeys(frame []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func requireEmptyParameters(parameters json.RawMessage) error {
	if len(parameters) == 0 {
		return errors.New("parameters must be an empty JSON object for system operations")
	}

	var values map[string]json.RawMessage
	if err := json.Unmarshal(parameters, &values); err != nil || values == nil {
		return errors.New("parameters must be a JSON object")
	}
	if len(values) != 0 {
		return errors.New("system operations do not accept parameters")
	}
	return nil
}

func successResponse(requestID string, result any) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       requestID,
		OK:              true,
		Result:          result,
	}
}

func errorResponse(requestID, code, message string) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       requestID,
		OK:              false,
		Error: &ProtocolError{
			Code:      code,
			Message:   message,
			Retryable: false,
		},
	}
}

func (p *Processor) handlePing(_ context.Context, request Request) Response {
	if err := requireEmptyParameters(request.Parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	return successResponse(request.RequestID, p.system.Liveness())
}

func (p *Processor) handleVersion(_ context.Context, request Request) Response {
	if err := requireEmptyParameters(request.Parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	info := p.system.Info()
	return successResponse(request.RequestID, VersionReport{
		Name:            info.Name,
		Version:         info.Version,
		Commit:          info.Commit,
		BuiltAt:         info.BuiltAt,
		GoVersion:       info.GoVersion,
		OS:              info.OS,
		Arch:            info.Arch,
		ProtocolVersion: ProtocolVersion,
		Operations:      Operations,
	})
}

func (p *Processor) handleReadiness(ctx context.Context, request Request) Response {
	if err := requireEmptyParameters(request.Parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	return successResponse(request.RequestID, p.system.Readiness(ctx))
}

func (p *Processor) handleMetrics(_ context.Context, request Request) Response {
	if err := requireEmptyParameters(request.Parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	return successResponse(request.RequestID, p.metrics.report(p.tenant != nil))
}
