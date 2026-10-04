import "net/http"

// @Service
// @NeedsAll
type ScimProvisioningService struct {
	engineHelper *EngineHelper
}

func (service *ScimProvisioningService) Create(request *http.Request, body ScimResourceCreateRequest, call EngineCall) error {
	return service.provision(request, ScimEngineCall{Body: body.Body}, call)
}

func (service *ScimProvisioningService) Resource(request *http.Request, body ScimResourceRequest, call EngineCall) error {
	return service.provision(request, ScimEngineCall{ResourceID: body.ResourceID}, call)
}

func (service *ScimProvisioningService) List(request *http.Request, body ScimListRequest, call EngineCall) error {
	return service.provision(request, ScimEngineCall{Filter: body.Filter, StartIndex: body.StartIndex, Count: body.Count}, call)
}

func (service *ScimProvisioningService) Patch(request *http.Request, body ScimResourcePatchRequest, call EngineCall) error {
	return service.provision(request, ScimEngineCall{ResourceID: body.ResourceID, Body: body.Body}, call)
}

func (service *ScimProvisioningService) provision(request *http.Request, parameters ScimEngineCall, call EngineCall) error {
	parameters.Token = HeaderUtils{}.BearerToken(request.Header)
	return service.engineHelper.Call(call.Operation, parameters, call.Result)
}
