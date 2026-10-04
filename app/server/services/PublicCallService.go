// @Service
// @NeedsAll
type PublicCallService struct {
	engineHelper *EngineHelper
}

func (service *PublicCallService) Call(call EngineCall) error {
	return service.engineHelper.Call(call.Operation, call.Parameters, call.Result)
}
