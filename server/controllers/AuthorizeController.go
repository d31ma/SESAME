import "net/http"

// @RequestRoute("/api/v1/authorize")
// @SignedIn
// @NeedsAll
type AuthorizeController struct {
	callerService *CallerService
	engineService *EngineService
}

// @PostRoute("/decide")
func (controller *AuthorizeController) PostDecide(
	request *http.Request,
	// @FromBody
	body AuthorizeDecideRequest,
) (AuthorizeDecision, error) {
	caller, failure := controller.callerService.Resolve(request)
	return controller.decide(controller.sessionDecide(caller, body), failure)
}

// @PostRoute("/decide-batch")
func (controller *AuthorizeController) PostDecideBatch(
	request *http.Request,
	// @FromBody
	body AuthorizeDecideBatchRequest,
) (AuthorizeDecisions, error) {
	caller, failure := controller.callerService.Resolve(request)
	return controller.decideBatch(controller.sessionBatch(caller, body), failure)
}

func (controller *AuthorizeController) decide(question AuthorizeSessionDecide, failure error) (AuthorizeDecision, error) {
	if failure != nil {
		return AuthorizeDecision{}, failure
	}
	var result AuthorizeDecision
	failure = controller.engineService.Call("authorize.decide", question, &result)
	return result, failure
}

func (controller *AuthorizeController) decideBatch(batch AuthorizeSessionBatch, failure error) (AuthorizeDecisions, error) {
	if failure != nil {
		return AuthorizeDecisions{}, failure
	}
	var result AuthorizeDecisions
	failure = controller.engineService.Call("authorize.decide_batch", batch, &result)
	return result, failure
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
