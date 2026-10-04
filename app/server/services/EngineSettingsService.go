import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Service
type EngineSettingsService struct{}

func (service *EngineSettingsService) Read() (EngineSettings, error) {
	snapshot := ApplicationSnapshot{}
	failure := json.Unmarshal([]byte(os.Getenv(service.snapshotVariable())), &snapshot)
	settings := service.withDefaultWait(snapshot.Yon.Sesame)
	return service.validated(settings, failure)
}

func (service *EngineSettingsService) RequireSamlConsumerURL(consumerURL string) error {
	settings, failure := service.Read()
	return service.requireListed(settings.SamlConsumerAddresses, consumerURL, failure)
}

func (service *EngineSettingsService) RequireFederationRedirectURI(redirectURI string) error {
	settings, failure := service.Read()
	return service.requireListed(settings.FederationRedirectAddresses, redirectURI, failure)
}

func (service *EngineSettingsService) requireListed(allowed []string, address string, failure error) error {
	if failure != nil || slices.Contains(allowed, address) {
		return failure
	}
	return &host.RedirectNotAllowedError{}
}

func (service *EngineSettingsService) validated(settings EngineSettings, failure error) (EngineSettings, error) {
	if !service.usable(settings, failure) {
		return EngineSettings{}, &host.EngineNotConfiguredError{}
	}
	return settings, nil
}

func (service *EngineSettingsService) usable(settings EngineSettings, failure error) bool {
	checks := []bool{
		failure == nil,
		filepath.IsAbs(settings.Binary),
		filepath.IsAbs(settings.Deployment),
		settings.WaitMilliseconds >= 0,
		settings.WaitMilliseconds <= service.longestWait(),
		!slices.ContainsFunc(settings.SamlConsumerAddresses, service.unsafeAddress),
		!slices.ContainsFunc(settings.FederationRedirectAddresses, service.unsafeAddress),
	}
	return !slices.Contains(checks, false)
}

func (service *EngineSettingsService) unsafeAddress(address string) bool {
	parsed, failure := url.Parse(address)
	if failure != nil {
		return true
	}
	checks := []bool{
		parsed.Scheme == service.secureScheme(),
		parsed.Host != "",
		!strings.Contains(address, service.fragmentMarker()),
	}
	return slices.Contains(checks, false)
}

func (service *EngineSettingsService) withDefaultWait(settings EngineSettings) EngineSettings {
	if settings.WaitMilliseconds == 0 {
		settings.WaitMilliseconds = service.defaultWait()
	}
	return settings
}

func (service *EngineSettingsService) snapshotVariable() string {
	return "YON_APPLICATION_JSON"
}

func (service *EngineSettingsService) defaultWait() int64 {
	return 5000
}

func (service *EngineSettingsService) longestWait() int64 {
	return 20000
}

func (service *EngineSettingsService) secureScheme() string {
	return "https"
}

func (service *EngineSettingsService) fragmentMarker() string {
	return "#"
}
