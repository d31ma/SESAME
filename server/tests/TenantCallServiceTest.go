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

func (test *TenantCallServiceTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *TenantCallServiceTest) calls() *TenantCallService {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &TenantCallService{callerService: &CallerService{engineService: engine}, engineService: engine}
}
