import "net/http"

// @RequestRoute("/oidc")
// @Public
// @NeedsAll
type StandardsController struct {
	standardsDispatchService *StandardsDispatchService
	standardsAnswerService   *StandardsAnswerService
}

// @GetRoute("/openid-configuration")
func (controller *StandardsController) GetDiscovery(request *http.Request) (*http.Response, error) {
	return controller.answer(request, "oidc.discovery")
}

// @GetRoute("/jwks")
func (controller *StandardsController) GetJwks(request *http.Request) (*http.Response, error) {
	return controller.answer(request, "oidc.jwks")
}

// @GetRoute("/authorize")
func (controller *StandardsController) GetAuthorization(request *http.Request) (*http.Response, error) {
	response, err := controller.standardsDispatchService.Dispatch(request, "oidc.authorization")
	return controller.standardsAnswerService.Authorize(response, err)
}

// @PostRoute("/token")
func (controller *StandardsController) PostToken(request *http.Request) (*http.Response, error) {
	return controller.answer(request, "oidc.token")
}

// @PostRoute("/introspect")
func (controller *StandardsController) PostIntrospection(request *http.Request) (*http.Response, error) {
	return controller.answer(request, "oidc.introspection")
}

// @PostRoute("/revoke")
func (controller *StandardsController) PostRevocation(request *http.Request) (*http.Response, error) {
	return controller.answer(request, "oidc.revocation")
}

// @GetRoute("/logout")
func (controller *StandardsController) GetLogout(request *http.Request) (*http.Response, error) {
	return controller.answer(request, "oidc.logout")
}

func (controller *StandardsController) answer(request *http.Request, endpoint string) (*http.Response, error) {
	response, err := controller.standardsDispatchService.Dispatch(request, endpoint)
	return controller.standardsAnswerService.Answer(response, err)
}
