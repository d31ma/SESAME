import "net/http"

// @Service
// @NeedsAll
type TenantCallService struct {
	callerService *CallerService
	engineService *EngineService
}

func (service *TenantCallService) Call(request *http.Request, tenantID string, call EngineCall) error {
	caller, failure := service.callerService.Resolve(request)
	failure = service.requireTenant(caller, tenantID, failure)
	return service.send(call, failure)
}

func (service *TenantCallService) requireTenant(caller Caller, tenantID string, failure error) error {
	if failure != nil {
		return failure
	}
	return service.callerService.RequireTenant(caller, tenantID)
}

func (service *TenantCallService) send(call EngineCall, failure error) error {
	if failure != nil {
		return failure
	}
	return service.engineService.Call(call.Operation, call.Parameters, call.Result)
}
