package machine

import (
	"errors"

	"github.com/d31ma/sesame/internal/application/identity"
)

func (p *Processor) handleInteractionGet(request Request) Response {
	if p.tenant == nil {
		return errorResponse(request.RequestID, ErrorStorageNotConfigured, "OIDC operations require a configured FYLO root")
	}
	var parameters struct {
		InteractionID     string  `json:"interaction_id"`
		InteractionSecret *string `json:"interaction_secret"`
	}
	if err := decodeParameters(request.Parameters, &parameters); err != nil {
		return errorResponse(request.RequestID, ErrorInvalidRequest, err.Error())
	}
	if parameters.InteractionSecret == nil {
		interaction, err := p.tenant.InteractionGet(parameters.InteractionID)
		if err != nil {
			return tenantErrorResponse(request.RequestID, err)
		}
		return successResponse(request.RequestID, interaction)
	}
	interaction, err := p.tenant.InteractionGetHeld(parameters.InteractionID, *parameters.InteractionSecret)
	if err != nil {
		return heldInteractionErrorResponse(request.RequestID, err)
	}
	return successResponse(request.RequestID, interaction)
}

func heldInteractionErrorResponse(requestID string, err error) Response {
	if errors.Is(err, identity.ErrInteractionNotFound) {
		return errorResponse(requestID, ErrorInteractionNotFound, "interaction not found")
	}
	return errorResponse(requestID, ErrorInternal, "interaction lookup failed")
}
