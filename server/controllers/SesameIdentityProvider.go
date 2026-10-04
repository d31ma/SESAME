import (
	"errors"
	"net/http"

	"github.com/d31ma/sesame/server/packages/host"
)

// @IdentityProvider
type SesameIdentityProvider struct{}

func (provider *SesameIdentityProvider) Identify(request *http.Request) (*Identity, error) {
	engineService := &EngineService{engineSettingsService: &EngineSettingsService{}}
	caller, failure := (&CallerService{engineService: engineService}).Resolve(request)
	roles, failure := provider.roles(&AdministratorService{engineService: engineService}, caller, failure)
	identity, failure := provider.identity(caller, roles, failure)
	return identity, provider.withoutRejection(failure)
}

func (provider *SesameIdentityProvider) roles(
	administratorService *AdministratorService,
	caller Caller,
	failure error,
) ([]string, error) {
	if failure != nil {
		return nil, failure
	}
	return administratorService.Roles(caller)
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
