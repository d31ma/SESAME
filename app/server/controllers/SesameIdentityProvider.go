import "net/http"

// @IdentityProvider
type SesameIdentityProvider struct{}

func (provider *SesameIdentityProvider) Identify(request *http.Request) (*Identity, error) {
	engineHelper := &EngineHelper{engineSettingsHelper: &EngineSettingsHelper{}}
	identityService := &IdentityService{
		callerService:        &CallerService{engineHelper: engineHelper},
		administratorService: &AdministratorService{engineHelper: engineHelper},
	}
	return identityService.Identify(request)
}
