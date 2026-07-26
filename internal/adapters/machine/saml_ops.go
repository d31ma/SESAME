package machine

import (
	"context"
	"errors"

	"github.com/d31ma/sesame/internal/application/identity"
	samldomain "github.com/d31ma/sesame/internal/domain/saml"
)

// Stable error codes for inbound SAML 2.0.
const (
	ErrorSAMLProviderNotFound = "saml_provider_not_found"
	ErrorSAMLLoginNotFound    = "saml_login_not_found"
	ErrorSAMLSubjectNotLinked = "saml_subject_not_linked"
	// ErrorSAMLAssertionRejected is one code for every way an assertion can
	// fail, for the same reason inbound OIDC has one: a caller who can tell a
	// bad signature from a wrong audience learns the shape of the flow. The
	// specific reason goes to the audit ledger.
	ErrorSAMLAssertionRejected = "saml_assertion_rejected"
)

// samlRoutes are the operations this slice adds.
func (p *Processor) samlRoutes() map[string]handlerFunc {
	return map[string]handlerFunc{
		"saml.provider_register": p.handleSAMLProviderRegister,
		"saml.provider_get":      withoutContext(p.handleSAMLProviderGet),
		"saml.provider_disable":  p.handleSAMLProviderDisable,
		"saml.login_start":       p.handleSAMLLoginStart,
		"saml.login_complete":    p.handleSAMLLoginComplete,
	}
}

// requireSAMLStorage is the one place SAML operations check that storage
// exists, so no handler can forget to.
func (p *Processor) requireSAMLStorage(request Request) *Response {
	if p.tenant == nil {
		response := errorResponse(request.RequestID, ErrorStorageNotConfigured,
			"SAML operations require a configured FYLO root")
		return &response
	}
	return nil
}

func (p *Processor) handleSAMLProviderRegister(ctx context.Context, request Request) Response {
	if unavailable := p.requireSAMLStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		Name     string `json:"name"`
		EntityID string `json:"entity_id"`
		SSOURL   string `json:"sso_url"`
		// Certificates arrive as PEM or bare base64, which is what metadata
		// documents and operators respectively supply.
		Certificates        []string `json:"certificates"`
		IdentifierNamespace string   `json:"identifier_namespace"`
		Linking             string   `json:"linking"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	provider, err := p.tenant.SAMLProviderRegister(ctx, parameters.TenantID,
		parameters.Name, parameters.EntityID, parameters.SSOURL,
		parameters.Certificates, parameters.IdentifierNamespace, parameters.Linking,
		"operator:machine")
	if err != nil {
		return samlErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, provider)
}

func (p *Processor) handleSAMLProviderGet(request Request) Response {
	if unavailable := p.requireSAMLStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID   string `json:"tenant_id"`
		ProviderID string `json:"provider_id"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	provider, err := p.tenant.SAMLProviderGet(parameters.TenantID, parameters.ProviderID)
	if err != nil {
		return samlErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, provider)
}

func (p *Processor) handleSAMLProviderDisable(ctx context.Context, request Request) Response {
	if unavailable := p.requireSAMLStorage(request); unavailable != nil {
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
	if err := p.tenant.SAMLProviderDisable(ctx, parameters.TenantID,
		parameters.ProviderID, parameters.Reason, "operator:machine"); err != nil {
		return samlErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, map[string]any{
		"provider_id": parameters.ProviderID, "disabled": true,
	})
}

func (p *Processor) handleSAMLLoginStart(ctx context.Context, request Request) Response {
	if unavailable := p.requireSAMLStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID   string `json:"tenant_id"`
		ProviderID string `json:"provider_id"`
		// ConsumerURL is where the host will receive the assertion. It is
		// echoed into the AuthnRequest and checked against the assertion's
		// Recipient on the way back.
		ConsumerURL string `json:"consumer_url"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	login, err := p.tenant.SAMLLoginStart(ctx, parameters.TenantID,
		parameters.ProviderID, parameters.ConsumerURL, "operator:machine")
	if err != nil {
		return samlErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, login)
}

func (p *Processor) handleSAMLLoginComplete(ctx context.Context, request Request) Response {
	if unavailable := p.requireSAMLStorage(request); unavailable != nil {
		return *unavailable
	}
	var parameters struct {
		TenantID string `json:"tenant_id"`
		LoginID  string `json:"login_id"`
		// Assertion is the base64 SAMLResponse exactly as the host received
		// it. The engine decodes, parses, and verifies it; the host is never
		// asked to have understood it.
		Assertion string `json:"assertion"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	document, err := samldomain.DecodeResponse(parameters.Assertion)
	if err != nil {
		return errorResponse(request.RequestID, ErrorSAMLAssertionRejected,
			"the SAML assertion was rejected")
	}
	result, err := p.tenant.SAMLLoginComplete(ctx, parameters.TenantID,
		parameters.LoginID, document, "operator:machine")
	if err != nil {
		return samlErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, result)
}

// samlErrorMap is the stable mapping from a domain error to a wire code.
var samlErrorMap = []struct {
	sentinel error
	code     string
	message  string
}{
	{identity.ErrSAMLProviderNotFound, ErrorSAMLProviderNotFound,
		"SAML identity provider not found"},
	{identity.ErrSAMLLoginNotFound, ErrorSAMLLoginNotFound, "SAML login not found"},
	{identity.ErrSAMLSubjectNotLinked, ErrorSAMLSubjectNotLinked,
		"no principal is linked to this SAML subject"},
	{identity.ErrSAMLAssertionRejected, ErrorSAMLAssertionRejected,
		"the SAML assertion was rejected"},
}

func samlErrorResponse(requestID string, err error) Response {
	for _, mapping := range samlErrorMap {
		if errors.Is(err, mapping.sentinel) {
			return errorResponse(requestID, mapping.code, mapping.message)
		}
	}
	// Anything else is a validation failure on operator-supplied input, whose
	// message describes the configuration and never a credential.
	return tenantErrorResponse(requestID, err)
}
