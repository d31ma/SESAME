// @Test(SesameTestSetup, {"partition":"tests"})
type SystemControllerTest struct {
	behaviors *BehaviorContext
}

func (test *SystemControllerTest) TestPingAnswersOk() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()

	ping, err := controller.PostPing()

	Assert.IsTrue(err == nil)
	Assert.Equals("ok", ping.Status)
}

func (test *SystemControllerTest) TestVersionNamesTheProtocolAndOperations() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()

	version, err := controller.PostVersion()

	Assert.IsTrue(err == nil)
	Assert.Equals("sesame", version.Name)
	Assert.Equals("1", version.ProtocolVersion)
	Assert.IsTrue(len(version.Operations) > 0)
}

func (test *SystemControllerTest) TestReadinessReportsStorageReady() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()

	readiness, err := controller.PostReadiness()

	Assert.IsTrue(err == nil)
	Assert.Equals("ok", readiness.Status)
}

func (test *SystemControllerTest) TestMetricsCountRequestsOfTheSameEngine() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()
	_, pingErr := controller.PostPing()

	metrics, err := controller.PostMetrics()

	Assert.IsTrue(pingErr == nil)
	Assert.IsTrue(err == nil)
	Assert.IsTrue(metrics.StorageConfigured)
	Assert.Equals(int64(1), metrics.RequestsTotal["system.ping"])
}

func (test *SystemControllerTest) controller() *SystemController {
	return &SystemController{engineService: &EngineService{engineSettingsService: &EngineSettingsService{}}}
}
