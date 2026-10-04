import (
	"encoding/json"
	"net/http"
)

// @Service
// @NeedsAll
type TenantCallService struct {
	callerService        *CallerService
	engineService        *EngineService
	administratorService *AdministratorService
	recentSignInService  *RecentSignInService
}

func (service *TenantCallService) Call(request *http.Request, tenantID string, call EngineCall) error {
	caller, failure := service.administrator(request, call)
	failure = service.sameTenant(caller, tenantID, failure)
	return service.send(call, failure)
}

func (service *TenantCallService) Load(request *http.Request, lookup EngineCall) error {
	caller, failure := service.administrator(request, lookup)
	return service.owned(caller, lookup, failure)
}

func (service *TenantCallService) CallOwned(request *http.Request, lookup EngineCall, call EngineCall) error {
	caller, failure := service.administrator(request, call)
	failure = service.owned(caller, lookup, failure)
	return service.send(call, failure)
}

func (service *TenantCallService) CallAsAdministrator(request *http.Request, call EngineCall) error {
	_, failure := service.administrator(request, call)
	return service.send(call, failure)
}

func (service *TenantCallService) CallAsCaller(request *http.Request, bind func(caller Caller) EngineCall) error {
	caller, failure := service.callerService.Resolve(request)
	call := bind(caller)
	failure = service.recentWhenPrivileged(caller, call, failure)
	return service.send(call, failure)
}

func (service *TenantCallService) LoadAsCaller(request *http.Request, lookup EngineCall) error {
	caller, failure := service.callerService.Resolve(request)
	return service.owned(caller, lookup, failure)
}

func (service *TenantCallService) administrator(request *http.Request, call EngineCall) (Caller, error) {
	caller, failure := service.callerService.Resolve(request)
	failure = service.administratorService.Require(caller, failure)
	return caller, service.recentWhenPrivileged(caller, call, failure)
}

func (service *TenantCallService) recentWhenPrivileged(caller Caller, call EngineCall, failure error) error {
	if !call.Privileged {
		return failure
	}
	return service.recentSignInService.Require(caller, failure)
}

func (service *TenantCallService) owned(caller Caller, lookup EngineCall, failure error) error {
	record, failure := service.fetch(lookup, failure)
	owner, failure := service.owner(record, failure)
	failure = service.sameTenant(caller, owner.TenantID, failure)
	return service.decoded(record, lookup.Result, failure)
}

func (service *TenantCallService) fetch(lookup EngineCall, failure error) (json.RawMessage, error) {
	if failure != nil {
		return nil, failure
	}
	record := json.RawMessage{}
	failure = service.engineService.Call(lookup.Operation, lookup.Parameters, &record)
	return record, failure
}

func (service *TenantCallService) owner(record json.RawMessage, failure error) (TenantOwner, error) {
	if failure != nil {
		return TenantOwner{}, failure
	}
	owner := TenantOwner{}
	failure = json.Unmarshal(record, &owner)
	return owner, failure
}

func (service *TenantCallService) sameTenant(caller Caller, tenantID string, failure error) error {
	if failure != nil {
		return failure
	}
	return service.callerService.RequireTenant(caller, tenantID)
}

func (service *TenantCallService) decoded(record json.RawMessage, result any, failure error) error {
	if failure != nil {
		return failure
	}
	return json.Unmarshal(record, result)
}

func (service *TenantCallService) send(call EngineCall, failure error) error {
	if failure != nil {
		return failure
	}
	return service.engineService.Call(call.Operation, call.Parameters, call.Result)
}
