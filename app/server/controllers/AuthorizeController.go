import "net/http"

// @RequestRoute("/api/v1/authorize")
// @SignedIn
// @NeedsAll
type AuthorizeController struct {
	tenantCallService *TenantCallService
}

// @PostRoute("/decide")
func (controller *AuthorizeController) PostDecide(
	request *http.Request,
	// @FromBody
	body AuthorizeDecideRequest,
) (AuthorizeDecision, error) {
	var result AuthorizeDecision
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		return EngineCall{Operation: "authorize.decide", Parameters: controller.sessionDecide(caller, body), Result: &result}
	})
	return result, err
}

// @PostRoute("/decide-batch")
func (controller *AuthorizeController) PostDecideBatch(
	request *http.Request,
	// @FromBody
	body AuthorizeDecideBatchRequest,
) (AuthorizeDecisions, error) {
	var result AuthorizeDecisions
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		return EngineCall{Operation: "authorize.decide_batch", Parameters: controller.sessionBatch(caller, body), Result: &result}
	})
	return result, err
}

func (controller *AuthorizeController) sessionDecide(caller Caller, body AuthorizeDecideRequest) AuthorizeSessionDecide {
	return AuthorizeSessionDecide{
		TenantID:      caller.TenantID,
		PrincipalID:   caller.PrincipalID,
		Action:        body.Action,
		Resource:      body.Resource,
		Context:       body.Context,
		SessionID:     caller.SessionID,
		SessionSecret: caller.SessionSecret,
		PolicyVersion: body.PolicyVersion,
	}
}

func (controller *AuthorizeController) sessionBatch(caller Caller, body AuthorizeDecideBatchRequest) AuthorizeSessionBatch {
	questions := make([]AuthorizeSessionQuestion, 0, len(body.Requests))
	for _, question := range body.Requests {
		questions = append(questions, controller.sessionQuestion(caller, question))
	}
	return AuthorizeSessionBatch{Requests: questions, PolicyVersion: body.PolicyVersion}
}

func (controller *AuthorizeController) sessionQuestion(caller Caller, question AuthorizeQuestion) AuthorizeSessionQuestion {
	return AuthorizeSessionQuestion{
		TenantID:      caller.TenantID,
		PrincipalID:   caller.PrincipalID,
		Action:        question.Action,
		Resource:      question.Resource,
		Context:       question.Context,
		SessionID:     caller.SessionID,
		SessionSecret: caller.SessionSecret,
	}
}
