type AuthorizeQuestionUtils struct{}

func (AuthorizeQuestionUtils) ForCaller(caller Caller, question AuthorizeQuestion) AuthorizeSessionQuestion {
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
