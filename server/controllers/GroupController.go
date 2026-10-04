import "net/http"

// @RequestRoute("/api/v1/group")
// @Allow(Administrator)
// @NeedsAll
type GroupController struct {
	principalTenantService *PrincipalTenantService
	tenantCallService      *TenantCallService
}

// @PostRoute("/member-add")
func (controller *GroupController) PostMemberAdd(
	request *http.Request,
	// @FromBody
	body GroupMemberRequest,
) (GroupMembership, error) {
	var result GroupMembership
	err := controller.principalTenantService.Call(request, body.PrincipalID, EngineCall{
		Operation:  "group.member_add",
		Parameters: body,
		Result:     &result,
		Privileged: true,
	})
	return result, err
}

// @PostRoute("/member-remove")
func (controller *GroupController) PostMemberRemove(
	request *http.Request,
	// @FromBody
	body GroupMemberRequest,
) (GroupMembership, error) {
	var result GroupMembership
	err := controller.principalTenantService.Call(request, body.PrincipalID, EngineCall{
		Operation:  "group.member_remove",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/create")
func (controller *GroupController) PostCreate(
	request *http.Request,
	// @FromBody
	body GroupCreateRequest,
) (Group, error) {
	var result Group
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "group.create",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}
