import "net/http"

// @RequestRoute("/api/v1/oidc")
// @NeedsAll
type OidcController struct {
	engineService            *EngineService
	tenantCallService        *TenantCallService
	interactionCookieService *InteractionCookieService
}

// @PostRoute("/interaction-get")
// @SignedIn
func (controller *OidcController) PostInteractionGet(
	request *http.Request,
	// @FromCookie("__Secure-sesame_interaction")
	interaction string,
) (OidcInteraction, error) {
	var result OidcInteraction
	handle := controller.interactionCookieService.Handle(interaction)
	err := controller.tenantCallService.LoadAsCaller(request, EngineCall{
		Operation:  "oidc.interaction_get",
		Parameters: handle,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/interaction-complete")
// @SignedIn
func (controller *OidcController) PostInteractionComplete(
	request *http.Request,
	// @FromCookie("__Secure-sesame_interaction")
	interaction string,
) (OidcAuthorizationCode, error) {
	var result OidcAuthorizationCode
	handle := controller.interactionCookieService.Handle(interaction)
	err := controller.tenantCallService.CallAsCaller(request, controller.completionFor(handle, &result))
	return result, err
}

// @PostRoute("/consent-grant")
// @SignedIn
func (controller *OidcController) PostConsentGrant(
	request *http.Request,
	// @FromBody
	body OidcConsentGrantRequest,
) (OidcConsent, error) {
	var result OidcConsent
	err := controller.tenantCallService.CallAsCaller(request, controller.grantFor(body, &result))
	return result, err
}

// @PostRoute("/consent-get")
// @SignedIn
func (controller *OidcController) PostConsentGet(
	request *http.Request,
	// @FromBody
	body OidcClientReference,
) (OidcConsent, error) {
	var result OidcConsent
	err := controller.tenantCallService.CallAsCaller(request, controller.consentFor("oidc.consent_get", body.ClientID, &result))
	return result, err
}

// @PostRoute("/consent-withdraw")
// @SignedIn
func (controller *OidcController) PostConsentWithdraw(
	request *http.Request,
	// @FromBody
	body OidcClientReference,
) (OidcConsentWithdrawn, error) {
	var result OidcConsentWithdrawn
	err := controller.tenantCallService.CallAsCaller(request, controller.consentFor("oidc.consent_withdraw", body.ClientID, &result))
	return result, err
}

// @PostRoute("/device-lookup")
// @SignedIn
func (controller *OidcController) PostDeviceLookup(
	request *http.Request,
	// @FromBody
	body OidcUserCodeRequest,
) (OidcDeviceRequest, error) {
	var result OidcDeviceRequest
	err := controller.tenantCallService.CallAsCaller(request, controller.userCodeFor("oidc.device_lookup", body.UserCode, &result))
	return result, err
}

// @PostRoute("/device-approve")
// @SignedIn
func (controller *OidcController) PostDeviceApprove(
	request *http.Request,
	// @FromBody
	body OidcUserCodeRequest,
) (OidcDeviceRequest, error) {
	var result OidcDeviceRequest
	err := controller.tenantCallService.CallAsCaller(request, controller.approvalFor(body.UserCode, &result))
	return result, err
}

// @PostRoute("/device-deny")
// @SignedIn
func (controller *OidcController) PostDeviceDeny(
	request *http.Request,
	// @FromBody
	body OidcUserCodeRequest,
) (OidcDeviceDenied, error) {
	var result OidcDeviceDenied
	err := controller.tenantCallService.CallAsCaller(request, controller.userCodeFor("oidc.device_deny", body.UserCode, &result))
	return result, err
}

// @PostRoute("/pushed-authorize")
// @Public
func (controller *OidcController) PostPushedAuthorize(
	// @FromBody
	body OidcPushedAuthorizeRequest,
) (OidcPushedRequest, error) {
	var result OidcPushedRequest
	err := controller.engineService.Call("oidc.pushed_authorize", body, &result)
	return result, err
}

// @PostRoute("/device-authorize")
// @Public
func (controller *OidcController) PostDeviceAuthorize(
	// @FromBody
	body OidcDeviceAuthorizeRequest,
) (OidcDeviceStarted, error) {
	var result OidcDeviceStarted
	err := controller.engineService.Call("oidc.device_authorize", body, &result)
	return result, err
}

// @PostRoute("/dpop-verify")
// @Public
func (controller *OidcController) PostDpopVerify(
	// @FromBody
	body OidcDpopVerifyRequest,
) (OidcDpopVerification, error) {
	var result OidcDpopVerification
	err := controller.engineService.Call("oidc.dpop_verify", body, &result)
	return result, err
}

// @PostRoute("/refresh-family-get")
// @Allow(Administrator)
func (controller *OidcController) PostRefreshFamilyGet(
	request *http.Request,
	// @FromBody
	body OidcRefreshFamilyReference,
) (OidcRefreshFamily, error) {
	var result OidcRefreshFamily
	err := controller.tenantCallService.Load(request, controller.familyLookup(body.FamilyID, &result))
	return result, err
}

// @PostRoute("/refresh-family-revoke")
// @Allow(Administrator)
func (controller *OidcController) PostRefreshFamilyRevoke(
	request *http.Request,
	// @FromBody
	body OidcRefreshFamilyRevokeRequest,
) (RevokeOutcome, error) {
	var result RevokeOutcome
	revoke := EngineCall{Operation: "oidc.refresh_family_revoke", Parameters: body, Result: &result}
	err := controller.tenantCallService.CallOwned(request, controller.familyLookup(body.FamilyID, &OidcRefreshFamily{}), revoke)
	return result, err
}

func (controller *OidcController) familyLookup(familyID string, result *OidcRefreshFamily) EngineCall {
	return EngineCall{
		Operation:  "oidc.refresh_family_get",
		Parameters: OidcRefreshFamilyReference{FamilyID: familyID},
		Result:     result,
	}
}

func (controller *OidcController) consentFor(operation string, clientID string, result any) func(caller Caller) EngineCall {
	return func(caller Caller) EngineCall {
		parameters := OidcConsentParameters{PrincipalID: caller.PrincipalID, ClientID: clientID}
		return EngineCall{Operation: operation, Parameters: parameters, Result: result}
	}
}

func (controller *OidcController) userCodeFor(operation string, userCode string, result any) func(caller Caller) EngineCall {
	return func(caller Caller) EngineCall {
		parameters := OidcUserCodeParameters{TenantID: caller.TenantID, UserCode: userCode}
		return EngineCall{Operation: operation, Parameters: parameters, Result: result}
	}
}

func (controller *OidcController) approvalFor(userCode string, result *OidcDeviceRequest) func(caller Caller) EngineCall {
	return func(caller Caller) EngineCall {
		return EngineCall{Operation: "oidc.device_approve", Result: result, Parameters: OidcDeviceApproval{
			TenantID:      caller.TenantID,
			UserCode:      userCode,
			SessionID:     caller.SessionID,
			SessionSecret: caller.SessionSecret,
		}}
	}
}

func (controller *OidcController) completionFor(handle OidcInteractionHandle, result *OidcAuthorizationCode) func(caller Caller) EngineCall {
	return func(caller Caller) EngineCall {
		return EngineCall{Operation: "oidc.interaction_complete", Result: result, Parameters: OidcInteractionCompletion{
			InteractionID:     handle.InteractionID,
			InteractionSecret: handle.InteractionSecret,
			SessionID:         caller.SessionID,
			SessionSecret:     caller.SessionSecret,
		}}
	}
}

func (controller *OidcController) grantFor(body OidcConsentGrantRequest, result *OidcConsent) func(caller Caller) EngineCall {
	return func(caller Caller) EngineCall {
		return EngineCall{Operation: "oidc.consent_grant", Result: result, Parameters: OidcConsentGrantParameters{
			SessionID:     caller.SessionID,
			SessionSecret: caller.SessionSecret,
			ClientID:      body.ClientID,
			Scopes:        body.Scopes,
		}}
	}
}
