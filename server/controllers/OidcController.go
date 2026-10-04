import "net/http"

// @RequestRoute("/api/v1/oidc")
// @NeedsAll
type OidcController struct {
	engineService            *EngineService
	callerCallService        *CallerCallService
	tenantRecordService      *TenantRecordService
	interactionCookieService *InteractionCookieService
}

// @PostRoute("/interaction-get")
// @SignedIn
func (controller *OidcController) PostInteractionGet(
	request *http.Request,
	// @FromCookie("sesame_interaction")
	interaction string,
) (result OidcInteraction, err error) {
	handle := controller.interactionCookieService.Handle(interaction)
	err = controller.tenantRecordService.Load(request, EngineCall{
		Operation:  "oidc.interaction_get",
		Parameters: OidcInteractionReference{InteractionID: handle.InteractionID},
		Result:     &result,
	})
	return
}

// @PostRoute("/interaction-complete")
// @SignedIn
func (controller *OidcController) PostInteractionComplete(
	request *http.Request,
	// @FromCookie("sesame_interaction")
	interaction string,
) (result OidcAuthorizationCode, err error) {
	handle := controller.interactionCookieService.Handle(interaction)
	err = controller.callerCallService.Call(request, controller.completionFor(handle, &result))
	return
}

// @PostRoute("/consent-grant")
// @SignedIn
func (controller *OidcController) PostConsentGrant(
	request *http.Request,
	// @FromBody
	body OidcConsentGrantRequest,
) (result OidcConsent, err error) {
	err = controller.callerCallService.Call(request, controller.grantFor(body, &result))
	return
}

// @PostRoute("/consent-get")
// @SignedIn
func (controller *OidcController) PostConsentGet(
	request *http.Request,
	// @FromBody
	body OidcConsentRequest,
) (result OidcConsent, err error) {
	err = controller.callerCallService.Call(request, controller.consentFor("oidc.consent_get", body.ClientID, &result))
	return
}

// @PostRoute("/consent-withdraw")
// @SignedIn
func (controller *OidcController) PostConsentWithdraw(
	request *http.Request,
	// @FromBody
	body OidcConsentRequest,
) (result OidcConsentWithdrawn, err error) {
	err = controller.callerCallService.Call(request, controller.consentFor("oidc.consent_withdraw", body.ClientID, &result))
	return
}

// @PostRoute("/device-lookup")
// @SignedIn
func (controller *OidcController) PostDeviceLookup(
	request *http.Request,
	// @FromBody
	body OidcUserCodeRequest,
) (result OidcDeviceRequest, err error) {
	err = controller.callerCallService.Call(request, controller.userCodeFor("oidc.device_lookup", body.UserCode, &result))
	return
}

// @PostRoute("/device-approve")
// @SignedIn
func (controller *OidcController) PostDeviceApprove(
	request *http.Request,
	// @FromBody
	body OidcUserCodeRequest,
) (result OidcDeviceRequest, err error) {
	err = controller.callerCallService.Call(request, controller.approvalFor(body.UserCode, &result))
	return
}

// @PostRoute("/device-deny")
// @SignedIn
func (controller *OidcController) PostDeviceDeny(
	request *http.Request,
	// @FromBody
	body OidcUserCodeRequest,
) (result OidcDeviceDenied, err error) {
	err = controller.callerCallService.Call(request, controller.userCodeFor("oidc.device_deny", body.UserCode, &result))
	return
}

// @PostRoute("/pushed-authorize")
// @Public
func (controller *OidcController) PostPushedAuthorize(
	// @FromBody
	body OidcPushedAuthorizeRequest,
) (result OidcPushedRequest, err error) {
	err = controller.engineService.Call("oidc.pushed_authorize", body, &result)
	return
}

// @PostRoute("/device-authorize")
// @Public
func (controller *OidcController) PostDeviceAuthorize(
	// @FromBody
	body OidcDeviceAuthorizeRequest,
) (result OidcDeviceStarted, err error) {
	err = controller.engineService.Call("oidc.device_authorize", body, &result)
	return
}

// @PostRoute("/dpop-verify")
// @Public
func (controller *OidcController) PostDpopVerify(
	// @FromBody
	body OidcDpopVerifyRequest,
) (result OidcDpopVerification, err error) {
	err = controller.engineService.Call("oidc.dpop_verify", body, &result)
	return
}

// @PostRoute("/refresh-family-get")
// @Allow(Administrator)
func (controller *OidcController) PostRefreshFamilyGet(
	request *http.Request,
	// @FromBody
	body OidcRefreshFamilyReference,
) (result OidcRefreshFamily, err error) {
	err = controller.tenantRecordService.Load(request, controller.familyLookup(body.FamilyID, &result))
	return
}

// @PostRoute("/refresh-family-revoke")
// @Allow(Administrator)
func (controller *OidcController) PostRefreshFamilyRevoke(
	request *http.Request,
	// @FromBody
	body OidcRefreshFamilyRevokeRequest,
) (result OidcRefreshFamilyRevoked, err error) {
	revoke := EngineCall{Operation: "oidc.refresh_family_revoke", Parameters: body, Result: &result}
	err = controller.tenantRecordService.Call(request, controller.familyLookup(body.FamilyID, &OidcRefreshFamily{}), revoke)
	return
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
