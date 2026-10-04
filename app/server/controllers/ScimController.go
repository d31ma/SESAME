import "net/http"

// @RequestRoute("/api/v1/scim")
// @NeedsAll
type ScimController struct {
	scimProvisioningService *ScimProvisioningService
	tenantCallService       *TenantCallService
}

// @PostRoute("/client-register")
// @Allow(Administrator)
func (controller *ScimController) PostClientRegister(
	request *http.Request,
	// @FromBody
	body ScimClientRegisterRequest,
) (ScimClientRegistration, error) {
	var result ScimClientRegistration
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "scim.client_register",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/client-rotate-token")
// @Allow(Administrator)
func (controller *ScimController) PostClientRotateToken(
	request *http.Request,
	// @FromBody
	body ScimClientRequest,
) (ScimClientToken, error) {
	var result ScimClientToken
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "scim.client_rotate_token",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/client-disable")
// @Allow(Administrator)
func (controller *ScimController) PostClientDisable(
	request *http.Request,
	// @FromBody
	body ScimClientDisableRequest,
) (DisableOutcome, error) {
	var result DisableOutcome
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "scim.client_disable",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/user-create")
// @Public
func (controller *ScimController) PostUserCreate(
	request *http.Request,
	// @FromBody
	body ScimResourceCreateRequest,
) (ScimUser, error) {
	var result ScimUser
	err := controller.scimProvisioningService.Create(request, body, EngineCall{Operation: "scim.user_create", Result: &result})
	return result, err
}

// @PostRoute("/user-get")
// @Public
func (controller *ScimController) PostUserGet(
	request *http.Request,
	// @FromBody
	body ScimResourceRequest,
) (ScimUser, error) {
	var result ScimUser
	err := controller.scimProvisioningService.Resource(request, body, EngineCall{Operation: "scim.user_get", Result: &result})
	return result, err
}

// @PostRoute("/user-list")
// @Public
func (controller *ScimController) PostUserList(
	request *http.Request,
	// @FromBody
	body ScimListRequest,
) (ScimUserList, error) {
	var result ScimUserList
	err := controller.scimProvisioningService.List(request, body, EngineCall{Operation: "scim.user_list", Result: &result})
	return result, err
}

// @PostRoute("/user-patch")
// @Public
func (controller *ScimController) PostUserPatch(
	request *http.Request,
	// @FromBody
	body ScimResourcePatchRequest,
) (ScimUser, error) {
	var result ScimUser
	err := controller.scimProvisioningService.Patch(request, body, EngineCall{Operation: "scim.user_patch", Result: &result})
	return result, err
}

// @PostRoute("/user-deprovision")
// @Public
func (controller *ScimController) PostUserDeprovision(
	request *http.Request,
	// @FromBody
	body ScimResourceRequest,
) (DeprovisionOutcome, error) {
	var result DeprovisionOutcome
	err := controller.scimProvisioningService.Resource(request, body, EngineCall{Operation: "scim.user_deprovision", Result: &result})
	return result, err
}

// @PostRoute("/group-create")
// @Public
func (controller *ScimController) PostGroupCreate(
	request *http.Request,
	// @FromBody
	body ScimResourceCreateRequest,
) (ScimGroup, error) {
	var result ScimGroup
	err := controller.scimProvisioningService.Create(request, body, EngineCall{Operation: "scim.group_create", Result: &result})
	return result, err
}

// @PostRoute("/group-get")
// @Public
func (controller *ScimController) PostGroupGet(
	request *http.Request,
	// @FromBody
	body ScimResourceRequest,
) (ScimGroup, error) {
	var result ScimGroup
	err := controller.scimProvisioningService.Resource(request, body, EngineCall{Operation: "scim.group_get", Result: &result})
	return result, err
}

// @PostRoute("/group-list")
// @Public
func (controller *ScimController) PostGroupList(
	request *http.Request,
	// @FromBody
	body ScimListRequest,
) (ScimGroupList, error) {
	var result ScimGroupList
	err := controller.scimProvisioningService.List(request, body, EngineCall{Operation: "scim.group_list", Result: &result})
	return result, err
}

// @PostRoute("/group-patch")
// @Public
func (controller *ScimController) PostGroupPatch(
	request *http.Request,
	// @FromBody
	body ScimResourcePatchRequest,
) (ScimGroup, error) {
	var result ScimGroup
	err := controller.scimProvisioningService.Patch(request, body, EngineCall{Operation: "scim.group_patch", Result: &result})
	return result, err
}

// @PostRoute("/group-deprovision")
// @Public
func (controller *ScimController) PostGroupDeprovision(
	request *http.Request,
	// @FromBody
	body ScimResourceRequest,
) (DeprovisionOutcome, error) {
	var result DeprovisionOutcome
	err := controller.scimProvisioningService.Resource(request, body, EngineCall{Operation: "scim.group_deprovision", Result: &result})
	return result, err
}
