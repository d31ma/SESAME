import "net/http"

// @RequestRoute("/api/v1/oidc-client")
// @Allow(Administrator)
// @NeedsAll
type OidcClientController struct {
	tenantCallService *TenantCallService
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
		Privileged: true,
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
	err := controller.tenantCallService.Load(request, controller.lookup(body.ClientID, &result))
	return result, err
}

// @PostRoute("/rotate-secret")
func (controller *OidcClientController) PostRotateSecret(
	request *http.Request,
	// @FromBody
	body OidcClientReference,
) (OidcClientSecret, error) {
	var result OidcClientSecret
	err := controller.tenantCallService.CallOwned(request, controller.lookup(body.ClientID, &OidcClient{}), EngineCall{
		Operation:  "oidc_client.rotate_secret",
		Parameters: body,
		Result:     &result,
		Privileged: true,
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
	err := controller.tenantCallService.CallOwned(request, controller.lookup(body.ClientID, &OidcClient{}), EngineCall{
		Operation:  "oidc_client.disable",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

func (controller *OidcClientController) lookup(clientID string, result *OidcClient) EngineCall {
	return EngineCall{
		Operation:  "oidc_client.get",
		Parameters: OidcClientReference{ClientID: clientID},
		Result:     result,
	}
}
