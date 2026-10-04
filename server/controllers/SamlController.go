import "net/http"

// @RequestRoute("/api/v1/saml")
// @NeedsAll
type SamlController struct {
	engineService     *EngineService
	tenantCallService *TenantCallService
}

// @PostRoute("/login-start")
// @Public
func (controller *SamlController) PostLoginStart(
	// @FromBody
	body SamlLoginStartRequest,
) (SamlLogin, error) {
	var result SamlLogin
	err := controller.engineService.Call("saml.login_start", body, &result)
	return result, err
}

// @PostRoute("/login-complete")
// @Public
func (controller *SamlController) PostLoginComplete(
	// @FromBody
	body SamlLoginCompleteRequest,
) (FederatedLoginResult, error) {
	var result FederatedLoginResult
	err := controller.engineService.Call("saml.login_complete", body, &result)
	return result, err
}

// @PostRoute("/provider-register")
// @Allow(Administrator)
func (controller *SamlController) PostProviderRegister(
	request *http.Request,
	// @FromBody
	body SamlProviderRegisterRequest,
) (SamlProvider, error) {
	var result SamlProvider
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "saml.provider_register",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/provider-get")
// @Allow(Administrator)
func (controller *SamlController) PostProviderGet(
	request *http.Request,
	// @FromBody
	body ProviderRequest,
) (SamlProvider, error) {
	var result SamlProvider
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "saml.provider_get",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/provider-disable")
// @Allow(Administrator)
func (controller *SamlController) PostProviderDisable(
	request *http.Request,
	// @FromBody
	body ProviderDisableRequest,
) (SamlProviderDisabled, error) {
	var result SamlProviderDisabled
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "saml.provider_disable",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}
