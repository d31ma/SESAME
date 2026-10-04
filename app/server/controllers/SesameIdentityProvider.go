import "net/http"

// @IdentityProvider
type SesameIdentityProvider struct{}

func (provider *SesameIdentityProvider) Identify(request *http.Request) (*Identity, error) {
	engineService := &EngineService{engineSettingsService: &EngineSettingsService{}}
	identityService := &IdentityService{
		callerService:        &CallerService{engineService: engineService},
		administratorService: &AdministratorService{engineService: engineService},
	}
	return identityService.Identify(request)
}
