import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Service
type EngineService struct {
	// @Needs
	engineSettingsService *EngineSettingsService
	opening               sync.Once
	client                *sesame.Client
	failure               error
}

func (service *EngineService) Call(operation string, parameters any, result any) error {
	service.opening.Do(service.open)
	return service.send(operation, parameters, result)
}

func (service *EngineService) open() {
	settings, failure := service.engineSettingsService.Read()
	client, failure := service.start(settings, failure)
	service.client = client
	service.failure = service.busyWhenOutOfTime(failure)
}

func (service *EngineService) start(settings EngineSettings, failure error) (*sesame.Client, error) {
	if failure != nil {
		return nil, failure
	}
	wait := time.Duration(settings.WaitMilliseconds) * time.Millisecond
	deadline, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return sesame.StartWhenAvailable(deadline, sesame.Options{
		Binary:     settings.Binary,
		Deployment: settings.Deployment,
	})
}

func (service *EngineService) send(operation string, parameters any, result any) error {
	if service.failure != nil {
		return service.failure
	}
	return service.client.Request(context.Background(), operation, parameters, result)
}

func (service *EngineService) busyWhenOutOfTime(failure error) error {
	if errors.Is(failure, sesame.ErrDeploymentLocked) {
		return &EngineBusyError{}
	}
	return failure
}
