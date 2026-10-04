import "net/http"

// @RequestRoute("/api/v1/grant")
// @Allow(Administrator)
// @NeedsAll
type GrantController struct {
	tenantCallService *TenantCallService
	callerService     *CallerService
	engineService     *EngineService
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

// @PostRoute("/revoke")
func (controller *GrantController) PostRevoke(
	request *http.Request,
	// @FromBody
	body GrantRevokeRequest,
) (GrantRevocation, error) {
	var result GrantRevocation
	_, err := controller.callerService.Resolve(request)
	err = controller.revoke(body, &result, err)
	return result, err
}

func (controller *GrantController) revoke(body GrantRevokeRequest, result *GrantRevocation, failure error) error {
	if failure != nil {
		return failure
	}
	return controller.engineService.Call("grant.revoke", body, result)
}
