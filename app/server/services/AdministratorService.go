import (
	"slices"

	"github.com/d31ma/sesame/app/server/packages/host"
)

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

func (service *AdministratorService) Require(caller Caller, failure error) error {
	roles, failure := service.rolesWhenKnown(caller, failure)
	return service.administrator(roles, failure)
}

func (service *AdministratorService) rolesWhenKnown(caller Caller, failure error) ([]string, error) {
	if failure != nil {
		return nil, failure
	}
	return service.Roles(caller)
}

func (service *AdministratorService) administrator(roles []string, failure error) error {
	if failure != nil || slices.Contains(roles, service.administratorRole()) {
		return failure
	}
	return &host.AdministratorRequiredError{}
}

func (service *AdministratorService) question(caller Caller) AuthorizeSessionQuestion {
	return AuthorizeSessionQuestion{
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
