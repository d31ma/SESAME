import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
)

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
	administrator := setup.SignIn("acme", true)
	controller := test.controller()
	_, pingErr := controller.PostPing()

	metrics, err := controller.PostMetrics(test.request(setup.Credential(administrator)))

	Assert.IsTrue(pingErr == nil)
	Assert.IsTrue(err == nil)
	Assert.IsTrue(metrics.StorageConfigured)
	Assert.Equals(int64(1), metrics.RequestsTotal["system.ping"])
}

func (test *SystemControllerTest) TestMetricsRefuseAMemberEvenWithoutTheRouteGuard() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignInMember("acme", "member")

	metrics, err := test.controller().PostMetrics(test.request(setup.Credential(member)))

	var refused *host.AdministratorRequiredError
	Assert.IsTrue(errors.As(err, &refused))
	Assert.Equals(0, len(metrics.RequestsTotal))
}

func (test *SystemControllerTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *SystemControllerTest) controller() *SystemController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &SystemController{engineService: engine, tenantCallService: &TenantCallService{
		callerService:        &CallerService{engineService: engine},
		engineService:        engine,
		administratorService: &AdministratorService{engineService: engine},
		recentSignInService:  &RecentSignInService{},
	}}
}
