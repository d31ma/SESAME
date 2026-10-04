import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Helper
type EngineSettingsHelper struct{}

func (helper *EngineSettingsHelper) Read() (EngineSettings, error) {
	snapshot := ApplicationSnapshot{}
	failure := json.Unmarshal([]byte(os.Getenv(helper.snapshotVariable())), &snapshot)
	settings := helper.withDefaultWait(snapshot.Yon.Sesame)
	return helper.validated(settings, failure)
}

func (helper *EngineSettingsHelper) validated(settings EngineSettings, failure error) (EngineSettings, error) {
	if !helper.usable(settings, failure) {
		return EngineSettings{}, &host.EngineNotConfiguredError{}
	}
	return settings, nil
}

func (helper *EngineSettingsHelper) usable(settings EngineSettings, failure error) bool {
	checks := []bool{
		failure == nil,
		filepath.IsAbs(settings.Binary),
		filepath.IsAbs(settings.Deployment),
		settings.WaitMilliseconds >= 0,
		settings.WaitMilliseconds <= helper.longestWait(),
		!slices.ContainsFunc(settings.SamlConsumerAddresses, helper.unsafeAddress),
		!slices.ContainsFunc(settings.FederationRedirectAddresses, helper.unsafeAddress),
	}
	return !slices.Contains(checks, false)
}

func (helper *EngineSettingsHelper) unsafeAddress(address string) bool {
	parsed, failure := url.Parse(address)
	if failure != nil {
		return true
	}
	checks := []bool{
		parsed.Scheme == helper.secureScheme(),
		parsed.Host != "",
		!strings.Contains(address, helper.fragmentMarker()),
	}
	return slices.Contains(checks, false)
}

func (helper *EngineSettingsHelper) withDefaultWait(settings EngineSettings) EngineSettings {
	if settings.WaitMilliseconds == 0 {
		settings.WaitMilliseconds = helper.defaultWait()
	}
	return settings
}

func (helper *EngineSettingsHelper) snapshotVariable() string {
	return "YON_APPLICATION_JSON"
}

func (helper *EngineSettingsHelper) defaultWait() int64 {
	return 5000
}

func (helper *EngineSettingsHelper) longestWait() int64 {
	return 20000
}

func (helper *EngineSettingsHelper) secureScheme() string {
	return "https"
}

func (helper *EngineSettingsHelper) fragmentMarker() string {
	return "#"
}
