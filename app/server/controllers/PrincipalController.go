import "net/http"

// @RequestRoute("/api/v1/principal")
// @Allow(Administrator)
// @NeedsAll
type PrincipalController struct {
	tenantCallService      *TenantCallService
	principalLookupService *PrincipalLookupService
	principalTenantService *PrincipalTenantService
}

// @PostRoute("/create")
func (controller *PrincipalController) PostCreate(
	request *http.Request,
	// @FromBody
	body PrincipalCreateRequest,
) (Principal, error) {
	var result Principal
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "principal.create",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/get")
func (controller *PrincipalController) PostGet(
	request *http.Request,
	// @FromBody
	body PrincipalGetRequest,
) (Principal, error) {
	return controller.principalLookupService.Get(request, body, EngineCall{Operation: "principal.get", Parameters: body})
}

// @PostRoute("/suspend")
func (controller *PrincipalController) PostSuspend(
	request *http.Request,
	// @FromBody
	body PrincipalReference,
) (Principal, error) {
	var result Principal
	err := controller.principalTenantService.Call(request, body.PrincipalID, EngineCall{
		Operation:  "principal.suspend",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}
