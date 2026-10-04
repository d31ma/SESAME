import "net/http"

// @Service
// @NeedsAll
type OidcClientTenantService struct {
	tenantCallService *TenantCallService
}

func (service *OidcClientTenantService) Call(request *http.Request, clientID string, call EngineCall) error {
	return service.tenantCallService.CallOwned(request, service.lookup(clientID), call)
}

func (service *OidcClientTenantService) lookup(clientID string) EngineCall {
	return EngineCall{
		Operation:  "oidc_client.get",
		Parameters: OidcClientReference{ClientID: clientID},
		Result:     &OidcClient{},
	}
}
