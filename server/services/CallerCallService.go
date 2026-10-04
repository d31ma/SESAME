import "net/http"

// @Service
// @NeedsAll
type CallerCallService struct {
	callerService *CallerService
	engineService *EngineService
}

func (service *CallerCallService) Call(request *http.Request, bind func(caller Caller) EngineCall) error {
	caller, failure := service.callerService.Resolve(request)
	return service.send(bind(caller), failure)
}

func (service *CallerCallService) send(call EngineCall, failure error) error {
	if failure != nil {
		return failure
	}
	return service.engineService.Call(call.Operation, call.Parameters, call.Result)
}
