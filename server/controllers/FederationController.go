import "net/http"

// @RequestRoute("/api/v1/federation")
// @NeedsAll
type FederationController struct {
	engineService         *EngineService
	engineSettingsService *EngineSettingsService
	tenantCallService     *TenantCallService
}

// @PostRoute("/provider-register")
// @Allow(Administrator)
func (controller *FederationController) PostProviderRegister(
	request *http.Request,
	// @FromBody
	body FederationProviderRegisterRequest,
) (FederationProviderRegistration, error) {
	var result FederationProviderRegistration
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "federation.provider_register",
		Parameters: body,
		Result:     &result,
		Privileged: true,
	})
	return result, err
}

// @PostRoute("/provider-configure")
// @Allow(Administrator)
func (controller *FederationController) PostProviderConfigure(
	request *http.Request,
	// @FromBody
	body FederationProviderConfigureRequest,
) (FederationProviderMetadata, error) {
	var result FederationProviderMetadata
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "federation.provider_configure",
		Parameters: body,
		Result:     &result,
		Privileged: true,
	})
	return result, err
}

// @PostRoute("/provider-get")
// @Allow(Administrator)
func (controller *FederationController) PostProviderGet(
	request *http.Request,
	// @FromBody
	body ProviderRequest,
) (FederationProviderView, error) {
	var result FederationProviderView
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "federation.provider_get",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/provider-disable")
// @Allow(Administrator)
func (controller *FederationController) PostProviderDisable(
	request *http.Request,
	// @FromBody
	body ProviderDisableRequest,
) (DisableOutcome, error) {
	var result DisableOutcome
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "federation.provider_disable",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/login-start")
// @Public
func (controller *FederationController) PostLoginStart(
	// @FromBody
	body FederationLoginStartRequest,
) (FederationLogin, error) {
	var result FederationLogin
	err := controller.engineSettingsService.RequireFederationRedirectURI(body.RedirectURI)
	err = controller.allowedCall(err, EngineCall{Operation: "federation.login_start", Parameters: body, Result: &result})
	return result, err
}

// @PostRoute("/login-complete")
// @Public
func (controller *FederationController) PostLoginComplete(
	// @FromBody
	body FederationLoginCompleteRequest,
) (FederatedLoginResult, error) {
	var result FederatedLoginResult
	err := controller.engineService.Call("federation.login_complete", body, &result)
	return result, err
}

func (controller *FederationController) allowedCall(failure error, call EngineCall) error {
	if failure != nil {
		return failure
	}
	return controller.engineService.Call(call.Operation, call.Parameters, call.Result)
}
