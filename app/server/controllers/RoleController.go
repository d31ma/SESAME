import "net/http"

// @RequestRoute("/api/v1/role")
// @Allow(Administrator)
// @NeedsAll
type RoleController struct {
	tenantCallService *TenantCallService
}

// @PostRoute("/create")
func (controller *RoleController) PostCreate(
	request *http.Request,
	// @FromBody
	body RoleCreateRequest,
) (Role, error) {
	var result Role
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "role.create",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}
