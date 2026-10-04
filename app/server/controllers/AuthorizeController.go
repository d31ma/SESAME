import "net/http"

// @RequestRoute("/api/v1/authorize")
// @SignedIn
// @NeedsAll
type AuthorizeController struct {
	authorizeService *AuthorizeService
}

// @PostRoute("/decide")
func (controller *AuthorizeController) PostDecide(
	request *http.Request,
	// @FromBody
	body AuthorizeDecideRequest,
) (AuthorizeDecision, error) {
	var result AuthorizeDecision
	err := controller.authorizeService.Decide(request, body, EngineCall{Operation: "authorize.decide", Result: &result})
	return result, err
}

// @PostRoute("/decide-batch")
func (controller *AuthorizeController) PostDecideBatch(
	request *http.Request,
	// @FromBody
	body AuthorizeDecideBatchRequest,
) (AuthorizeDecisions, error) {
	var result AuthorizeDecisions
	err := controller.authorizeService.DecideBatch(request, body, EngineCall{Operation: "authorize.decide_batch", Result: &result})
	return result, err
}
