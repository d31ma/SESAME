import "net/http"

// @Service
// @NeedsAll
type OidcDeviceService struct {
	tenantCallService *TenantCallService
}

func (service *OidcDeviceService) UserCode(request *http.Request, body OidcUserCodeRequest, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = OidcUserCodeParameters{TenantID: caller.TenantID, UserCode: body.UserCode}
		return call
	})
}

func (service *OidcDeviceService) Approve(request *http.Request, body OidcUserCodeRequest, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = OidcDeviceApproval{
			TenantID:      caller.TenantID,
			UserCode:      body.UserCode,
			SessionID:     caller.SessionID,
			SessionSecret: caller.SessionSecret,
		}
		return call
	})
}
