import "net/http"

// @RequestRoute("/oidc")
// @Public
// @NeedsAll
type StandardsController struct {
	standardsEndpointService *StandardsEndpointService
}

// @GetRoute("/openid-configuration")
func (controller *StandardsController) GetDiscovery(request *http.Request) (*http.Response, error) {
	return controller.standardsEndpointService.Answer(request, "oidc.discovery")
}

// @GetRoute("/jwks")
func (controller *StandardsController) GetJwks(request *http.Request) (*http.Response, error) {
	return controller.standardsEndpointService.Answer(request, "oidc.jwks")
}

// @GetRoute("/authorize")
func (controller *StandardsController) GetAuthorization(request *http.Request) (*http.Response, error) {
	return controller.standardsEndpointService.Authorize(request, "oidc.authorization")
}

// @PostRoute("/token")
func (controller *StandardsController) PostToken(request *http.Request) (*http.Response, error) {
	return controller.standardsEndpointService.Answer(request, "oidc.token")
}

// @PostRoute("/introspect")
func (controller *StandardsController) PostIntrospection(request *http.Request) (*http.Response, error) {
	return controller.standardsEndpointService.Answer(request, "oidc.introspection")
}

// @PostRoute("/revoke")
func (controller *StandardsController) PostRevocation(request *http.Request) (*http.Response, error) {
	return controller.standardsEndpointService.Answer(request, "oidc.revocation")
}

// @GetRoute("/logout")
func (controller *StandardsController) GetLogout(request *http.Request) (*http.Response, error) {
	return controller.standardsEndpointService.Answer(request, "oidc.logout")
}
