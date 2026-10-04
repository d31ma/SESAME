import (
	"net/http"
	"strings"
)

// @RequestRoute("/api/v1/scim")
// @NeedsAll
type ScimController struct {
	engineService     *EngineService
	tenantCallService *TenantCallService
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
	err := controller.provision(request, "scim.user_create", ScimEngineCall{Body: body.Body}, &result)
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
	err := controller.provision(request, "scim.user_get", ScimEngineCall{ResourceID: body.ResourceID}, &result)
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
	err := controller.provision(request, "scim.user_list", controller.listCall(body), &result)
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
	err := controller.provision(request, "scim.user_patch", controller.patchCall(body), &result)
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
	err := controller.provision(request, "scim.user_deprovision", ScimEngineCall{ResourceID: body.ResourceID}, &result)
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
	err := controller.provision(request, "scim.group_create", ScimEngineCall{Body: body.Body}, &result)
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
	err := controller.provision(request, "scim.group_get", ScimEngineCall{ResourceID: body.ResourceID}, &result)
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
	err := controller.provision(request, "scim.group_list", controller.listCall(body), &result)
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
	err := controller.provision(request, "scim.group_patch", controller.patchCall(body), &result)
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
	err := controller.provision(request, "scim.group_deprovision", ScimEngineCall{ResourceID: body.ResourceID}, &result)
	return result, err
}

func (controller *ScimController) provision(request *http.Request, operation string, call ScimEngineCall, result any) error {
	call.Token = controller.bearerToken(request)
	return controller.engineService.Call(operation, call, result)
}

func (controller *ScimController) bearerToken(request *http.Request) string {
	scheme, token, _ := strings.Cut(request.Header.Get(controller.authorizationHeader()), " ")
	if !strings.EqualFold(scheme, controller.bearerScheme()) {
		return ""
	}
	return strings.TrimSpace(token)
}

func (controller *ScimController) listCall(body ScimListRequest) ScimEngineCall {
	return ScimEngineCall{Filter: body.Filter, StartIndex: body.StartIndex, Count: body.Count}
}

func (controller *ScimController) patchCall(body ScimResourcePatchRequest) ScimEngineCall {
	return ScimEngineCall{ResourceID: body.ResourceID, Body: body.Body}
}

func (controller *ScimController) authorizationHeader() string {
	return "Authorization"
}

func (controller *ScimController) bearerScheme() string {
	return "Bearer"
}
