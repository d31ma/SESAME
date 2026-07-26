package machine

import (
	"context"
	"errors"

	"github.com/d31ma/sesame/internal/application/identity"
	federationdomain "github.com/d31ma/sesame/internal/domain/federation"
)

// Stable error codes for inbound OIDC federation.
const (
	ErrorProviderNotFound      = "provider_not_found"
	ErrorProviderNotConfigured = "provider_not_configured"
	ErrorFederatedLoginMissing = "federated_login_not_found"
	ErrorFederatedLoginClosed  = "federated_login_closed"
	ErrorFederatedLoginExpired = "federated_login_expired"
	ErrorSubjectNotLinked      = "subject_not_linked"
	// ErrorAssertionRejected is deliberately one code for every way an
	// assertion can fail verification. A caller who can tell "wrong nonce"
	// from "unknown key" from "bad signature" learns the shape of the flow;
	// the specific reason goes to the audit ledger instead.
	ErrorAssertionRejected = "assertion_rejected"
	// ErrorProviderDocument covers a discovery document or key set that does
	// not survive validation.
	ErrorProviderDocument = "provider_document_rejected"
)

// federationRoutes are the operations this slice adds.
//
// They are a separate table merged into the processor's routes so the
// federation surface can be read in one place, rather than as six entries
// spread through fifty.
func (p *Processor) federationRoutes() map[string]handlerFunc {
	return map[string]handlerFunc{
		"federation.provider_register":  p.handleProviderRegister,
		"federation.provider_configure": p.handleProviderConfigure,
		"federation.provider_get":       withoutContext(p.handleProviderGet),
		"federation.provider_disable":   p.handleProviderDisable,
		"federation.login_start":        p.handleFederatedLoginStart,
		"federation.login_exchange":     p.handleFederatedLoginExchange,
		"federation.login_complete":     p.handleFederatedLoginComplete,
	}
}

// withoutContext adapts a read-only handler to the routed signature.
func withoutContext(handler func(Request) Response) handlerFunc {
	return func(_ context.Context, request Request) Response {
		return handler(request)
	}
}

// requireFederationStorage is the one place federation operations check that
// storage exists, so no handler can forget to.
func (p *Processor) requireFederationStorage(request Request) *Response {
	if p.tenant == nil {
		response := errorResponse(request.RequestID, ErrorStorageNotConfigured,
			"federation operations require a configured FYLO root")
		return &response
	}
	return nil
}

func (p *Processor) handleProviderRegister(ctx context.Context, request Request) Response {
	if unavailable := p.requireFederationStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID     string   `json:"tenant_id"`
		Name         string   `json:"name"`
		Issuer       string   `json:"issuer"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		Scopes       []string `json:"scopes"`
		SubjectClaim string   `json:"subject_claim"`
		EmailClaim   string   `json:"email_claim"`
		Linking      string   `json:"linking"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	provider, instruction, err := p.tenant.ProviderRegister(ctx,
		parameters.TenantID, parameters.Name, parameters.Issuer,
		parameters.ClientID, parameters.ClientSecret, parameters.Scopes,
		parameters.SubjectClaim, parameters.EmailClaim, parameters.Linking,
		"operator:machine")
	if err != nil {
		return federationErrorResponse(request.RequestID, err)
	}
	// The instruction travels with the provider: registration is not usable
	// until the host fetches what it names.
	return successResponse(request.RequestID, map[string]any{
		"provider": provider,
		"fetch":    instruction,
	})
}

func (p *Processor) handleProviderConfigure(ctx context.Context, request Request) Response {
	if unavailable := p.requireFederationStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID   string `json:"tenant_id"`
		ProviderID string `json:"provider_id"`
		// Both documents arrive as the bytes the host fetched. They are
		// parsed and validated in the engine, never by the caller.
		Discovery string `json:"discovery_document"`
		KeySet    string `json:"key_set_document"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	metadata, err := p.tenant.ProviderConfigure(ctx, parameters.TenantID, parameters.ProviderID,
		[]byte(parameters.Discovery), []byte(parameters.KeySet), "operator:machine")
	if err != nil {
		return federationErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, metadata)
}

func (p *Processor) handleProviderGet(request Request) Response {
	if unavailable := p.requireFederationStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID   string `json:"tenant_id"`
		ProviderID string `json:"provider_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	provider, err := p.tenant.ProviderGet(parameters.TenantID, parameters.ProviderID)
	if err != nil {
		return federationErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, provider)
}

func (p *Processor) handleFederatedLoginStart(ctx context.Context, request Request) Response {
	if unavailable := p.requireFederationStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID    string `json:"tenant_id"`
		ProviderID  string `json:"provider_id"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	login, err := p.tenant.LoginStart(ctx, parameters.TenantID, parameters.ProviderID,
		parameters.RedirectURI, "operator:machine")
	if err != nil {
		return federationErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, login)
}

func (p *Processor) handleFederatedLoginExchange(ctx context.Context, request Request) Response {
	if unavailable := p.requireFederationStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		LoginID  string `json:"login_id"`
		State    string `json:"state"`
		Code     string `json:"code"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	instruction, err := p.tenant.LoginExchange(ctx, parameters.TenantID, parameters.LoginID,
		parameters.State, parameters.Code)
	if err != nil {
		return federationErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, instruction)
}

func (p *Processor) handleFederatedLoginComplete(ctx context.Context, request Request) Response {
	if unavailable := p.requireFederationStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		LoginID  string `json:"login_id"`
		IDToken  string `json:"id_token"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	result, err := p.tenant.LoginComplete(ctx, parameters.TenantID, parameters.LoginID,
		parameters.IDToken, "operator:machine")
	if err != nil {
		return federationErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

// federationErrorMap is the stable mapping from a domain error to a wire code.
//
// A table rather than a chain of errors.Is calls: adding a case is one line
// and does not make the mapping function harder to reason about.
var federationErrorMap = []struct {
	sentinel error
	code     string
	message  string
}{
	{identity.ErrProviderNotFound, ErrorProviderNotFound, "identity provider not found"},
	{identity.ErrProviderNotConfigured, ErrorProviderNotConfigured,
		"identity provider has no validated metadata; fetch its discovery document first"},
	{identity.ErrFederatedLoginNotFound, ErrorFederatedLoginMissing, "federated login not found"},
	{identity.ErrSubjectNotLinked, ErrorSubjectNotLinked,
		"no principal is linked to this external subject"},
	{identity.ErrAssertionRejected, ErrorAssertionRejected,
		"the provider's assertion was rejected"},
}

// federationErrorResponse maps a federation failure onto the wire.
func federationErrorResponse(requestID string, err error) Response {
	for _, mapping := range federationErrorMap {
		if errors.Is(err, mapping.sentinel) {
			return errorResponse(requestID, mapping.code, mapping.message)
		}
	}
	if code, matched := federationLoginStateCode(err); matched {
		return errorResponse(requestID, code, err.Error())
	}
	// Anything else is a validation failure on operator- or provider-supplied
	// input, and its message is safe to return: it describes the document,
	// never a credential.
	return tenantErrorResponse(requestID, err)
}

// federationLoginStateCode distinguishes a spent transaction from an expired
// one. Both are refusals, but the operator remedy differs: start again versus
// start again sooner.
func federationLoginStateCode(err error) (string, bool) {
	switch {
	case errors.Is(err, federationdomain.ErrLoginExpired):
		return ErrorFederatedLoginExpired, true
	case errors.Is(err, federationdomain.ErrLoginNotPending):
		return ErrorFederatedLoginClosed, true
	default:
		return "", false
	}
}

func (p *Processor) handleProviderDisable(ctx context.Context, request Request) Response {
	if unavailable := p.requireFederationStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID   string `json:"tenant_id"`
		ProviderID string `json:"provider_id"`
		Reason     string `json:"reason"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if err := p.tenant.ProviderDisable(ctx, parameters.TenantID, parameters.ProviderID,
		parameters.Reason, "operator:machine"); err != nil {
		return federationErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]bool{"disabled": true})
}
