import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
	"github.com/d31ma/sesame/app/server/packages/sesame"
)

// @Service
type EngineService struct {
	// @Needs
	engineSettingsService *EngineSettingsService
	opening               sync.Once
	client                *sesame.Client
	failure               error
	actor                 *sesame.Actor
}

func (service *EngineService) Call(operation string, parameters any, result any) error {
	service.opening.Do(service.open)
	failure := service.attributable(service.failure)
	return service.send(service.attribution(), EngineCall{Operation: operation, Parameters: parameters, Result: result}, failure)
}

func (service *EngineService) ActAs(caller Caller) {
	service.actor = &sesame.Actor{TenantID: caller.TenantID, PrincipalID: caller.PrincipalID, SessionID: caller.SessionID}
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

func (service *EngineService) attributable(failure error) error {
	if failure != nil || service.actor == nil {
		return failure
	}
	return service.client.RequireActor()
}

func (service *EngineService) attribution() context.Context {
	if service.actor == nil {
		return context.Background()
	}
	return sesame.WithActor(context.Background(), *service.actor)
}

func (service *EngineService) send(attribution context.Context, call EngineCall, failure error) error {
	if failure != nil {
		return failure
	}
	return service.client.Request(attribution, call.Operation, call.Parameters, call.Result)
}

func (service *EngineService) busyWhenOutOfTime(failure error) error {
	if errors.Is(failure, context.DeadlineExceeded) {
		return &host.EngineBusyError{}
	}
	return failure
}
