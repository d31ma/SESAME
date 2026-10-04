import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type TenantCallServiceTest struct {
	behaviors *BehaviorContext
}

func (test *TenantCallServiceTest) TestCallRunsTheOperationInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	tenant := map[string]any{}

	err := test.calls().Call(test.request(setup.Credential(session)), session.TenantID, EngineCall{
		Operation:  "tenant.get",
		Parameters: map[string]string{"tenant_id": session.TenantID},
		Result:     &tenant,
	})

	Assert.IsTrue(err == nil)
	Assert.Equals(session.TenantID, tenant["tenant_id"])
}

func (test *TenantCallServiceTest) TestCallRefusesAnotherTenantBeforeTheOperationRuns() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	tenant := map[string]any{}

	err := test.calls().Call(test.request(setup.Credential(session)), other.TenantID, EngineCall{
		Operation:  "tenant.get",
		Parameters: map[string]string{"tenant_id": other.TenantID},
		Result:     &tenant,
	})

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals(0, len(tenant))
}

func (test *TenantCallServiceTest) TestCallRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	tenant := map[string]any{}

	err := test.calls().Call(httptest.NewRequest(http.MethodPost, "/", nil), session.TenantID, EngineCall{
		Operation:  "tenant.get",
		Parameters: map[string]string{"tenant_id": session.TenantID},
		Result:     &tenant,
	})

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
	Assert.Equals(0, len(tenant))
}

func (test *TenantCallServiceTest) TestAdministrativeCallsRefuseAMemberBeforeTheOperationRuns() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignInMember("acme", "member")
	calls := test.calls()
	request := test.request(setup.Credential(member))
	tenant := map[string]any{}
	lookup := test.tenantLookup(member.TenantID, &tenant)

	refusals := []error{
		calls.Call(request, member.TenantID, lookup),
		calls.Load(request, lookup),
		calls.CallOwned(request, lookup, lookup),
		calls.CallAsAdministrator(request, lookup),
	}

	Assert.IsTrue(test.allRefused(refusals))
	Assert.Equals(0, len(tenant))
}

func (test *TenantCallServiceTest) TestCallerCallsRunForAMember() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignInMember("acme", "member")
	tenant := map[string]any{}

	err := test.calls().CallAsCaller(test.request(setup.Credential(member)), func(caller Caller) EngineCall {
		return test.tenantLookup(caller.TenantID, &tenant)
	})

	Assert.IsTrue(err == nil)
	Assert.Equals(member.TenantID, tenant["tenant_id"])
}

func (test *TenantCallServiceTest) allRefused(failures []error) bool {
	for _, failure := range failures {
		var refused *host.AdministratorRequiredError
		if !errors.As(failure, &refused) {
			return false
		}
	}
	return true
}

func (test *TenantCallServiceTest) tenantLookup(tenantID string, result *map[string]any) EngineCall {
	return EngineCall{Operation: "tenant.get", Parameters: map[string]string{"tenant_id": tenantID}, Result: result}
}

func (test *TenantCallServiceTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *TenantCallServiceTest) calls() *TenantCallService {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return test.tenantCalls(engine)
}

func (test *TenantCallServiceTest) tenantCalls(engine *EngineService) *TenantCallService {
	return &TenantCallService{
		callerService:        &CallerService{engineService: engine},
		engineService:        engine,
		administratorService: &AdministratorService{engineService: engine},
		recentSignInService:  &RecentSignInService{},
	}
}
