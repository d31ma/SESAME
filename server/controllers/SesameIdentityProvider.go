import (
	"errors"
	"net/http"

	"github.com/d31ma/sesame/server/packages/host"
)

// @IdentityProvider
// @NeedsAll
type SesameIdentityProvider struct {
	callerService        *CallerService
	administratorService *AdministratorService
}

func (provider *SesameIdentityProvider) Identify(request *http.Request) (*Identity, error) {
	caller, failure := provider.callerService.Resolve(request)
	roles, failure := provider.roles(caller, failure)
	identity, failure := provider.identity(caller, roles, failure)
	return identity, provider.withoutRejection(failure)
}

func (provider *SesameIdentityProvider) roles(caller Caller, failure error) ([]string, error) {
	if failure != nil {
		return nil, failure
	}
	return provider.administratorService.Roles(caller)
}

func (provider *SesameIdentityProvider) identity(caller Caller, roles []string, failure error) (*Identity, error) {
	if failure != nil {
		return nil, failure
	}
	return &Identity{User: caller.PrincipalID, Roles: roles}, nil
}

func (provider *SesameIdentityProvider) withoutRejection(failure error) error {
	rejected := &host.SessionRejectedError{}
	if errors.As(failure, &rejected) {
		return nil
	}
	return failure
}
