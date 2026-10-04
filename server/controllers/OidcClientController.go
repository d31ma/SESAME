import "net/http"

// @RequestRoute("/api/v1/oidc-client")
// @Allow(Administrator)
// @NeedsAll
type OidcClientController struct {
	tenantCallService   *TenantCallService
	tenantRecordService *TenantRecordService
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
	err := controller.tenantRecordService.Load(request, controller.lookup(body.ClientID, &result))
	return result, err
}

// @PostRoute("/rotate-secret")
func (controller *OidcClientController) PostRotateSecret(
	request *http.Request,
	// @FromBody
	body OidcClientReference,
) (OidcClientSecret, error) {
	var result OidcClientSecret
	err := controller.tenantRecordService.Call(request, controller.lookup(body.ClientID, &OidcClient{}), EngineCall{
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
) (OidcClientDisabled, error) {
	var result OidcClientDisabled
	err := controller.tenantRecordService.Call(request, controller.lookup(body.ClientID, &OidcClient{}), EngineCall{
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
