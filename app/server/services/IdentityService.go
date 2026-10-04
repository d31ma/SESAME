import (
	"errors"
	"net/http"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Service
// @NeedsAll
type IdentityService struct {
	callerService        *CallerService
	administratorService *AdministratorService
}

func (service *IdentityService) Identify(request *http.Request) (*Identity, error) {
	caller, failure := service.callerService.Resolve(request)
	roles, failure := service.roles(caller, failure)
	identity, failure := service.identity(caller, roles, failure)
	return identity, service.withoutRejection(failure)
}

func (service *IdentityService) roles(caller Caller, failure error) ([]string, error) {
	if failure != nil {
		return nil, failure
	}
	return service.administratorService.Roles(caller)
}

func (service *IdentityService) identity(caller Caller, roles []string, failure error) (*Identity, error) {
	if failure != nil {
		return nil, failure
	}
	return &Identity{User: caller.PrincipalID, Roles: roles}, nil
}

func (service *IdentityService) withoutRejection(failure error) error {
	rejected := &host.SessionRejectedError{}
	if errors.As(failure, &rejected) {
		return nil
	}
	return failure
}
