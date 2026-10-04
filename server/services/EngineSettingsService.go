import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	"github.com/d31ma/sesame/server/packages/host"
)

// @Service
type EngineSettingsService struct{}

func (service *EngineSettingsService) Read() (EngineSettings, error) {
	snapshot := ApplicationSnapshot{}
	failure := json.Unmarshal([]byte(os.Getenv(service.snapshotVariable())), &snapshot)
	settings := service.withDefaultWait(snapshot.Yon.Sesame)
	return service.validated(settings, failure)
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
	}
	return !slices.Contains(checks, false)
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
