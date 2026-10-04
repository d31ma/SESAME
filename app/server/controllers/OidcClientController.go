import "net/http"

// @RequestRoute("/api/v1/oidc-client")
// @Allow(Administrator)
// @NeedsAll
type OidcClientController struct {
	tenantCallService       *TenantCallService
	oidcClientTenantService *OidcClientTenantService
}

// @PostRoute("/register")
func (controller *OidcClientController) PostRegister(
	request *http.Request,
	// @FromBody
	body OidcClientRegisterRequest,
) (OidcClientRegistration, error) {
	var result OidcClientRegistration
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "oidc_client.register",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/get")
func (controller *OidcClientController) PostGet(
	request *http.Request,
	// @FromBody
	body OidcClientReference,
) (OidcClient, error) {
	var result OidcClient
	err := controller.tenantCallService.Load(request, EngineCall{Operation: "oidc_client.get", Parameters: body, Result: &result})
	return result, err
}

// @PostRoute("/rotate-secret")
func (controller *OidcClientController) PostRotateSecret(
	request *http.Request,
	// @FromBody
	body OidcClientReference,
) (OidcClientSecret, error) {
	var result OidcClientSecret
	err := controller.oidcClientTenantService.Call(request, body.ClientID, EngineCall{
		Operation:  "oidc_client.rotate_secret",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/disable")
func (controller *OidcClientController) PostDisable(
	request *http.Request,
	// @FromBody
	body OidcClientDisableRequest,
) (DisableOutcome, error) {
	var result DisableOutcome
	err := controller.oidcClientTenantService.Call(request, body.ClientID, EngineCall{
		Operation:  "oidc_client.disable",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}
