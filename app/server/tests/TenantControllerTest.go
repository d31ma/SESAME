import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type TenantControllerTest struct {
	behaviors *BehaviorContext
}

func (test *TenantControllerTest) TestGetReturnsTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)

	tenant, err := test.controller().PostGet(setup.SignedIn(session), TenantGetRequest{TenantID: session.TenantID})

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

	tenant, err := test.controller().PostGet(setup.SignedIn(session), TenantGetRequest{TenantID: other.TenantID})

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

func (test *TenantControllerTest) controller() *TenantController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	calls := SesameTestSetup{}.TenantCalls(engine)
	return &TenantController{tenantCallService: calls}
}
