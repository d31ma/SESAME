import "net/http"

// @RequestRoute("/api/v1/grant")
// @Allow(Administrator)
// @NeedsAll
type GrantController struct {
	tenantCallService *TenantCallService
}

// @PostRoute("/create")
func (controller *GrantController) PostCreate(
	request *http.Request,
	// @FromBody
	body GrantCreateRequest,
) (Grant, error) {
	var result Grant
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "grant.create",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}
