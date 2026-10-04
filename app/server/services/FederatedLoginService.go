import (
	"slices"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Service
// @NeedsAll
type FederatedLoginService struct {
	engineHelper         *EngineHelper
	engineSettingsHelper *EngineSettingsHelper
}

func (service *FederatedLoginService) StartFederation(redirectURI string, call EngineCall) error {
	settings, failure := service.engineSettingsHelper.Read()
	failure = service.requireListed(settings.FederationRedirectAddresses, redirectURI, failure)
	return service.allowedCall(call, failure)
}

func (service *FederatedLoginService) StartSaml(consumerURL string, call EngineCall) error {
	settings, failure := service.engineSettingsHelper.Read()
	failure = service.requireListed(settings.SamlConsumerAddresses, consumerURL, failure)
	return service.allowedCall(call, failure)
}

func (service *FederatedLoginService) requireListed(allowed []string, address string, failure error) error {
	if failure != nil || slices.Contains(allowed, address) {
		return failure
	}
	return &host.RedirectNotAllowedError{}
}

func (service *FederatedLoginService) allowedCall(call EngineCall, failure error) error {
	if failure != nil {
		return failure
	}
	return service.engineHelper.Call(call.Operation, call.Parameters, call.Result)
}
