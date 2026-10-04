import "net/http"

// @Service
// @NeedsAll
type PrincipalTenantService struct {
	callerService *CallerService
	engineService *EngineService
}

func (service *PrincipalTenantService) Require(request *http.Request, principalID string) (Principal, error) {
	caller, failure := service.callerService.Resolve(request)
	principal, failure := service.load(principalID, failure)
	failure = service.sameTenant(caller, principal, failure)
	return service.owned(principal, failure)
}

func (service *PrincipalTenantService) load(principalID string, failure error) (Principal, error) {
	if failure != nil {
		return Principal{}, failure
	}
	principal := Principal{}
	failure = service.engineService.Call("principal.get", PrincipalReference{PrincipalID: principalID}, &principal)
	return principal, failure
}

func (service *PrincipalTenantService) sameTenant(caller Caller, principal Principal, failure error) error {
	if failure != nil {
		return failure
	}
	return service.callerService.RequireTenant(caller, principal.TenantID)
}

func (service *PrincipalTenantService) owned(principal Principal, failure error) (Principal, error) {
	if failure != nil {
		return Principal{}, failure
	}
	return principal, nil
}
