import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type TenantControllerTest struct {
	behaviors *BehaviorContext
}

func (test *TenantControllerTest) TestGetReturnsTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)

	tenant, err := test.controller().PostGet(test.request(setup.Credential(session)), TenantGetRequest{TenantID: session.TenantID})

	Assert.IsTrue(err == nil)
	Assert.Equals(session.TenantID, tenant.TenantID)
	Assert.Equals("acme", tenant.Name)
	Assert.Equals("active", tenant.Status)
}

func (test *TenantControllerTest) TestGetRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)

	tenant, err := test.controller().PostGet(test.request(setup.Credential(session)), TenantGetRequest{TenantID: other.TenantID})

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", tenant.Name)
}

func (test *TenantControllerTest) TestGetRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)

	_, err := test.controller().PostGet(httptest.NewRequest(http.MethodPost, "/", nil), TenantGetRequest{TenantID: session.TenantID})

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
}

func (test *TenantControllerTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *TenantControllerTest) controller() *TenantController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	calls := &TenantCallService{callerService: &CallerService{engineService: engine}, engineService: engine}
	return &TenantController{tenantCallService: calls}
}
