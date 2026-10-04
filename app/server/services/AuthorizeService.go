import "net/http"

// @Service
// @NeedsAll
type AuthorizeService struct {
	tenantCallService *TenantCallService
}

func (service *AuthorizeService) Decide(request *http.Request, body AuthorizeDecideRequest, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = service.sessionDecide(caller, body)
		return call
	})
}

func (service *AuthorizeService) DecideBatch(request *http.Request, body AuthorizeDecideBatchRequest, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = service.sessionBatch(caller, body)
		return call
	})
}

func (service *AuthorizeService) sessionDecide(caller Caller, body AuthorizeDecideRequest) AuthorizeSessionDecide {
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

func (service *AuthorizeService) sessionBatch(caller Caller, body AuthorizeDecideBatchRequest) AuthorizeSessionBatch {
	questions := make([]AuthorizeSessionQuestion, 0, len(body.Requests))
	for _, question := range body.Requests {
		questions = append(questions, AuthorizeQuestionUtils{}.ForCaller(caller, question))
	}
	return AuthorizeSessionBatch{Requests: questions, PolicyVersion: body.PolicyVersion}
}
