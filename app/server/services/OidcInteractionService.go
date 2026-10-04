import "net/http"

// @Service
// @NeedsAll
type OidcInteractionService struct {
	tenantCallService *TenantCallService
}

func (service *OidcInteractionService) Interaction(request *http.Request, cookie string, call EngineCall) error {
	call.Parameters = InteractionCookieUtils{}.Handle(cookie)
	return service.tenantCallService.LoadAsCaller(request, call)
}

func (service *OidcInteractionService) CompleteInteraction(request *http.Request, cookie string, call EngineCall) error {
	handle := InteractionCookieUtils{}.Handle(cookie)
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = OidcInteractionCompletion{
			InteractionID:     handle.InteractionID,
			InteractionSecret: handle.InteractionSecret,
			SessionID:         caller.SessionID,
			SessionSecret:     caller.SessionSecret,
		}
		return call
	})
}

func (service *OidcInteractionService) GrantConsent(request *http.Request, body OidcConsentGrantRequest, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = OidcConsentGrantParameters{
			SessionID:     caller.SessionID,
			SessionSecret: caller.SessionSecret,
			ClientID:      body.ClientID,
			Scopes:        body.Scopes,
		}
		return call
	})
}

func (service *OidcInteractionService) Consent(request *http.Request, body OidcClientReference, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = OidcConsentParameters{PrincipalID: caller.PrincipalID, ClientID: body.ClientID}
		return call
	})
}
