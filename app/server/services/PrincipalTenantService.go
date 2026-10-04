import "net/http"

// @Service
// @NeedsAll
type PrincipalTenantService struct {
	tenantCallService *TenantCallService
}

func (service *PrincipalTenantService) Require(request *http.Request, principalID string) (Principal, error) {
	principal := Principal{}
	failure := service.tenantCallService.Load(request, service.lookup(principalID, &principal))
	return principal, failure
}

func (service *PrincipalTenantService) Call(request *http.Request, principalID string, call EngineCall) error {
	return service.tenantCallService.CallOwned(request, service.lookup(principalID, &Principal{}), call)
}

func (service *PrincipalTenantService) lookup(principalID string, result *Principal) EngineCall {
	return EngineCall{
		Operation:  "principal.get",
		Parameters: PrincipalReference{PrincipalID: principalID},
		Result:     result,
	}
}
