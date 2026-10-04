import (
	"encoding/json"
	"errors"
	"maps"
	"slices"

	"github.com/d31ma/sesame/app/server/packages/host"
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

func (test *SystemControllerTest) TestVersionAnswersOnlyWhatAClientNeeds() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()

	version, err := controller.PostVersion()
	encoded, _ := json.Marshal(version)

	Assert.IsTrue(err == nil)
	Assert.Equals("sesame", version.Name)
	Assert.Equals("1", version.ProtocolVersion)
	Assert.IsTrue(version.Version != "")
	Assert.Equals([]string{"name", "protocol_version", "version"}, test.fieldNames(encoded))
}

func (test *SystemControllerTest) TestBuildDescribesTheEngineToAnAdministrator() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	build, err := test.controller().PostBuild(setup.SignedIn(administrator))

	Assert.IsTrue(err == nil)
	Assert.Equals("sesame", build.Name)
	Assert.Equals("1", build.ProtocolVersion)
	Assert.IsTrue(build.GoVersion != "")
	Assert.IsTrue(len(build.Operations) > 0)
}

func (test *SystemControllerTest) TestBuildRefusesAMemberEvenWithoutTheRouteGuard() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignInMember("acme", "member")

	build, err := test.controller().PostBuild(setup.SignedIn(member))

	var refused *host.AdministratorRequiredError
	Assert.IsTrue(errors.As(err, &refused))
	Assert.Equals("", build.GoVersion)
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

	metrics, err := controller.PostMetrics(setup.SignedIn(administrator))

	Assert.IsTrue(pingErr == nil)
	Assert.IsTrue(err == nil)
	Assert.IsTrue(metrics.StorageConfigured)
	Assert.Equals(int64(1), metrics.RequestsTotal["system.ping"])
}

func (test *SystemControllerTest) TestMetricsRefuseAMemberEvenWithoutTheRouteGuard() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignInMember("acme", "member")

	metrics, err := test.controller().PostMetrics(setup.SignedIn(member))

	var refused *host.AdministratorRequiredError
	Assert.IsTrue(errors.As(err, &refused))
	Assert.Equals(0, len(metrics.RequestsTotal))
}

func (test *SystemControllerTest) fieldNames(encoded []byte) []string {
	fields := map[string]any{}
	_ = json.Unmarshal(encoded, &fields)
	names := slices.Collect(maps.Keys(fields))
	slices.Sort(names)
	return names
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
