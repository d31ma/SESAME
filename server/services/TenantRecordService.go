import (
	"encoding/json"
	"net/http"
)

// @Service
// @NeedsAll
type TenantRecordService struct {
	callerService *CallerService
	engineService *EngineService
}

func (service *TenantRecordService) Load(request *http.Request, lookup EngineCall) error {
	caller, failure := service.callerService.Resolve(request)
	record, failure := service.fetch(lookup, failure)
	owner, failure := service.owner(record, failure)
	failure = service.sameTenant(caller, owner, failure)
	return service.decoded(record, lookup.Result, failure)
}

func (service *TenantRecordService) Call(request *http.Request, lookup EngineCall, call EngineCall) error {
	failure := service.Load(request, lookup)
	return service.send(call, failure)
}

func (service *TenantRecordService) fetch(lookup EngineCall, failure error) (json.RawMessage, error) {
	if failure != nil {
		return nil, failure
	}
	record := json.RawMessage{}
	failure = service.engineService.Call(lookup.Operation, lookup.Parameters, &record)
	return record, failure
}

func (service *TenantRecordService) owner(record json.RawMessage, failure error) (TenantOwner, error) {
	if failure != nil {
		return TenantOwner{}, failure
	}
	owner := TenantOwner{}
	failure = json.Unmarshal(record, &owner)
	return owner, failure
}

func (service *TenantRecordService) sameTenant(caller Caller, owner TenantOwner, failure error) error {
	if failure != nil {
		return failure
	}
	return service.callerService.RequireTenant(caller, owner.TenantID)
}

func (service *TenantRecordService) decoded(record json.RawMessage, result any, failure error) error {
	if failure != nil {
		return failure
	}
	return json.Unmarshal(record, result)
}

func (service *TenantRecordService) send(call EngineCall, failure error) error {
	if failure != nil {
		return failure
	}
	return service.engineService.Call(call.Operation, call.Parameters, call.Result)
}
