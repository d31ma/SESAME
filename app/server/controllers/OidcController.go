import "net/http"

// @RequestRoute("/api/v1/oidc")
// @NeedsAll
type OidcController struct {
	oidcInteractionService     *OidcInteractionService
	oidcDeviceService          *OidcDeviceService
	publicCallService          *PublicCallService
	tenantCallService          *TenantCallService
	refreshFamilyTenantService *RefreshFamilyTenantService
}

// @PostRoute("/interaction-get")
// @SignedIn
func (controller *OidcController) PostInteractionGet(
	request *http.Request,
	// @FromCookie("__Secure-sesame_interaction")
	interaction string,
) (OidcInteraction, error) {
	var result OidcInteraction
	err := controller.oidcInteractionService.Interaction(request, interaction, EngineCall{Operation: "oidc.interaction_get", Result: &result})
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
	err := controller.oidcInteractionService.CompleteInteraction(request, interaction, EngineCall{
		Operation: "oidc.interaction_complete",
		Result:    &result,
	})
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
	err := controller.oidcInteractionService.GrantConsent(request, body, EngineCall{Operation: "oidc.consent_grant", Result: &result})
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
	err := controller.oidcInteractionService.Consent(request, body, EngineCall{Operation: "oidc.consent_get", Result: &result})
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
	err := controller.oidcInteractionService.Consent(request, body, EngineCall{Operation: "oidc.consent_withdraw", Result: &result})
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
	err := controller.oidcDeviceService.UserCode(request, body, EngineCall{Operation: "oidc.device_lookup", Result: &result})
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
	err := controller.oidcDeviceService.Approve(request, body, EngineCall{Operation: "oidc.device_approve", Result: &result})
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
	err := controller.oidcDeviceService.UserCode(request, body, EngineCall{Operation: "oidc.device_deny", Result: &result})
	return result, err
}

// @PostRoute("/pushed-authorize")
// @Public
func (controller *OidcController) PostPushedAuthorize(
	// @FromBody
	body OidcPushedAuthorizeRequest,
) (OidcPushedRequest, error) {
	var result OidcPushedRequest
	err := controller.publicCallService.Call(EngineCall{Operation: "oidc.pushed_authorize", Parameters: body, Result: &result})
	return result, err
}

// @PostRoute("/device-authorize")
// @Public
func (controller *OidcController) PostDeviceAuthorize(
	// @FromBody
	body OidcDeviceAuthorizeRequest,
) (OidcDeviceStarted, error) {
	var result OidcDeviceStarted
	err := controller.publicCallService.Call(EngineCall{Operation: "oidc.device_authorize", Parameters: body, Result: &result})
	return result, err
}

// @PostRoute("/dpop-verify")
// @Public
func (controller *OidcController) PostDpopVerify(
	// @FromBody
	body OidcDpopVerifyRequest,
) (OidcDpopVerification, error) {
	var result OidcDpopVerification
	err := controller.publicCallService.Call(EngineCall{Operation: "oidc.dpop_verify", Parameters: body, Result: &result})
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
	err := controller.tenantCallService.Load(request, EngineCall{Operation: "oidc.refresh_family_get", Parameters: body, Result: &result})
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
	err := controller.refreshFamilyTenantService.Call(request, body.FamilyID, EngineCall{
		Operation:  "oidc.refresh_family_revoke",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}
