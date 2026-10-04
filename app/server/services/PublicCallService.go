// @Service
// @NeedsAll
type PublicCallService struct {
	engineService *EngineService
}

func (service *PublicCallService) Call(call EngineCall) error {
	return service.engineService.Call(call.Operation, call.Parameters, call.Result)
}
