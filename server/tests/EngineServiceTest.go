import (
	"errors"
	"time"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type EngineServiceTest struct {
	behaviors *BehaviorContext
}

func (test *EngineServiceTest) TestCallReturnsTheEngineResult() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	var readiness SystemReadiness
	err := test.engine().Call("system.readiness", struct{}{}, &readiness)

	Assert.IsTrue(err == nil)
	Assert.Equals("ok", readiness.Status)
}

func (test *EngineServiceTest) TestCallReturnsProtocolErrorsUnchanged() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	err := test.engine().Call("system.unknown", struct{}{}, &SystemPing{})

	var protocolError *sesame.ProtocolError
	Assert.IsTrue(errors.As(err, &protocolError))
	Assert.Equals("operation_not_found", protocolError.Code)
}

func (test *EngineServiceTest) TestCallAnswersBusyWhenAnotherEngineHoldsTheDeployment() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	holder := setup.Open()
	defer holder.Close()
	setup.UseWait(300)

	started := time.Now()
	err := test.engine().Call("system.ping", struct{}{}, &SystemPing{})
	waited := time.Since(started)

	var busy *host.EngineBusyError
	Assert.IsTrue(errors.As(err, &busy))
	Assert.IsTrue(waited >= 300*time.Millisecond)
	Assert.IsTrue(waited < 5*time.Second)
}

func (test *EngineServiceTest) TestCallAnswersBusyWhenTheEngineCannotStartWithinTheWait() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	setup.UseWait(1)

	err := test.engine().Call("system.ping", struct{}{}, &SystemPing{})

	var busy *host.EngineBusyError
	Assert.IsTrue(errors.As(err, &busy))
}

func (test *EngineServiceTest) TestCallWaitsForTheDeploymentToBeReleased() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	holder := setup.Open()
	go setup.CloseLater(holder, 200*time.Millisecond)

	err := test.engine().Call("system.ping", struct{}{}, &SystemPing{})

	Assert.IsTrue(err == nil)
}

func (test *EngineServiceTest) TestCallUsesOneEnginePerInvocation() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	engine := test.engine()
	firstErr := engine.Call("system.ping", struct{}{}, &SystemPing{})

	var metrics SystemMetrics
	secondErr := engine.Call("system.metrics", struct{}{}, &metrics)

	Assert.IsTrue(firstErr == nil)
	Assert.IsTrue(secondErr == nil)
	Assert.Equals(int64(1), metrics.RequestsTotal["system.ping"])
}

func (test *EngineServiceTest) TestCallUsesTheDefaultWaitWhenNoneIsSet() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	setup.UseSettings(map[string]any{"binary": setup.binary, "deployment": setup.deployment})

	err := test.engine().Call("system.ping", struct{}{}, &SystemPing{})

	Assert.IsTrue(err == nil)
}

func (test *EngineServiceTest) TestCallRefusesSettingsWithoutPaths() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	Assert.IsTrue(test.refuses(setup, map[string]any{}))
}

func (test *EngineServiceTest) TestCallRefusesARelativeBinary() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	Assert.IsTrue(test.refuses(setup, map[string]any{"binary": "sesame", "deployment": setup.deployment}))
}

func (test *EngineServiceTest) TestCallRefusesARelativeDeployment() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	Assert.IsTrue(test.refuses(setup, map[string]any{"binary": setup.binary, "deployment": "deployment"}))
}

func (test *EngineServiceTest) TestCallRefusesAWaitPastTheLimit() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	Assert.IsTrue(test.refuses(setup, map[string]any{
		"binary": setup.binary, "deployment": setup.deployment, "waitmilliseconds": 20001,
	}))
}

func (test *EngineServiceTest) TestCallRefusesANegativeWait() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	Assert.IsTrue(test.refuses(setup, map[string]any{
		"binary": setup.binary, "deployment": setup.deployment, "waitmilliseconds": -1,
	}))
}

func (test *EngineServiceTest) TestCallRefusesWithoutTheApplicationSnapshot() {
	setup := SesameTestSetup{}.Provision()
	setup.Remove()

	err := test.engine().Call("system.ping", struct{}{}, &SystemPing{})

	var notConfigured *host.EngineNotConfiguredError
	Assert.IsTrue(errors.As(err, &notConfigured))
}

func (test *EngineServiceTest) refuses(setup *SesameTestSetup, settings map[string]any) bool {
	setup.UseSettings(settings)
	err := test.engine().Call("system.ping", struct{}{}, &SystemPing{})
	var notConfigured *host.EngineNotConfiguredError
	return errors.As(err, &notConfigured)
}

func (test *EngineServiceTest) engine() *EngineService {
	return &EngineService{engineSettingsService: &EngineSettingsService{}}
}
