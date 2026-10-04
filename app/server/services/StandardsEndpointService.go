import "net/http"

// @Service
// @NeedsAll
type StandardsEndpointService struct {
	standardsDispatchService *StandardsDispatchService
	standardsAnswerService   *StandardsAnswerService
}

func (service *StandardsEndpointService) Answer(request *http.Request, endpoint string) (*http.Response, error) {
	response, failure := service.standardsDispatchService.Dispatch(request, endpoint)
	return service.standardsAnswerService.Answer(response, failure)
}

func (service *StandardsEndpointService) Authorize(request *http.Request, endpoint string) (*http.Response, error) {
	response, failure := service.standardsDispatchService.Dispatch(request, endpoint)
	return service.standardsAnswerService.Authorize(response, failure)
}
