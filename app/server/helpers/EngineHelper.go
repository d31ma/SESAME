import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
	"github.com/d31ma/sesame/app/server/packages/sesame"
)

// @Helper
// @Needs(EngineSettingsHelper)
type EngineHelper struct {
	engineSettingsHelper *EngineSettingsHelper
	opening              sync.Once
	client               *sesame.Client
	failure              error
	actor                *sesame.Actor
}

func (helper *EngineHelper) Call(operation string, parameters any, result any) error {
	helper.opening.Do(helper.open)
	failure := helper.attributable(helper.failure)
	return helper.send(helper.attribution(), EngineCall{Operation: operation, Parameters: parameters, Result: result}, failure)
}

func (helper *EngineHelper) ActAs(caller Caller) {
	helper.actor = &sesame.Actor{TenantID: caller.TenantID, PrincipalID: caller.PrincipalID, SessionID: caller.SessionID}
}

func (helper *EngineHelper) open() {
	settings, failure := helper.engineSettingsHelper.Read()
	client, failure := helper.start(settings, failure)
	helper.client = client
	helper.failure = helper.busyWhenOutOfTime(failure)
}

func (helper *EngineHelper) start(settings EngineSettings, failure error) (*sesame.Client, error) {
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

func (helper *EngineHelper) attributable(failure error) error {
	if failure != nil || helper.actor == nil {
		return failure
	}
	return helper.client.RequireActor()
}

func (helper *EngineHelper) attribution() context.Context {
	if helper.actor == nil {
		return context.Background()
	}
	return sesame.WithActor(context.Background(), *helper.actor)
}

func (helper *EngineHelper) send(attribution context.Context, call EngineCall, failure error) error {
	if failure != nil {
		return failure
	}
	return helper.client.Request(attribution, call.Operation, call.Parameters, call.Result)
}

func (helper *EngineHelper) busyWhenOutOfTime(failure error) error {
	if errors.Is(failure, context.DeadlineExceeded) {
		return &host.EngineBusyError{}
	}
	return failure
}
