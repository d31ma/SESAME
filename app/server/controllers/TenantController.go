import "net/http"

// @RequestRoute("/api/v1/tenant")
// @Allow(Administrator)
// @NeedsAll
type TenantController struct {
	tenantCallService *TenantCallService
}

// @PostRoute("/get")
func (controller *TenantController) PostGet(
	request *http.Request,
	// @FromBody
	body TenantGetRequest,
) (Tenant, error) {
	var result Tenant
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "tenant.get",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}
