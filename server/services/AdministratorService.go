import "slices"

// @Service
// @NeedsAll
type AdministratorService struct {
	engineService *EngineService
}

func (service *AdministratorService) Roles(caller Caller) ([]string, error) {
	answer := AdministratorAnswer{}
	failure := service.engineService.Call("authorize.decide", service.question(caller), &answer)
	return service.roles(answer, failure), failure
}

func (service *AdministratorService) question(caller Caller) AdministratorQuestion {
	return AdministratorQuestion{
		TenantID:      caller.TenantID,
		PrincipalID:   caller.PrincipalID,
		Action:        service.action(),
		Resource:      service.resource(),
		SessionID:     caller.SessionID,
		SessionSecret: caller.SessionSecret,
	}
}

func (service *AdministratorService) roles(answer AdministratorAnswer, failure error) []string {
	checks := []bool{failure == nil, answer.Decision == service.allow()}
	if slices.Contains(checks, false) {
		return []string{}
	}
	return []string{service.administratorRole()}
}

func (service *AdministratorService) action() string {
	return "sesame:administer"
}

func (service *AdministratorService) resource() string {
	return "sesame:tenant"
}

func (service *AdministratorService) allow() string {
	return "allow"
}

func (service *AdministratorService) administratorRole() string {
	return "Administrator"
}
