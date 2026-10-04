import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type CallerServiceTest struct {
	behaviors *BehaviorContext
}

func (test *CallerServiceTest) TestResolveReturnsTheSessionCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)

	caller, err := test.callers().Resolve(test.request(setup.Credential(session)))

	Assert.IsTrue(err == nil)
	Assert.Equals(session.TenantID, caller.TenantID)
	Assert.Equals(session.PrincipalID, caller.PrincipalID)
	Assert.Equals(session.SessionID, caller.SessionID)
}

func (test *CallerServiceTest) TestResolveRejectsAMissingCredential() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	_, err := test.callers().Resolve(httptest.NewRequest(http.MethodPost, "/", nil))

	Assert.IsTrue(test.rejected(err))
}

func (test *CallerServiceTest) TestResolveRejectsACredentialWithoutASecret() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)

	_, err := test.callers().Resolve(test.request(session.SessionID))

	Assert.IsTrue(test.rejected(err))
}

func (test *CallerServiceTest) TestResolveRejectsAWrongSecret() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)

	_, err := test.callers().Resolve(test.request(session.SessionID + ":not-the-secret"))

	Assert.IsTrue(test.rejected(err))
}

func (test *CallerServiceTest) TestResolveRejectsAnUnknownSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	_, err := test.callers().Resolve(test.request("not-a-session:not-a-secret"))

	Assert.IsTrue(test.rejected(err))
}

func (test *CallerServiceTest) TestResolveRejectsARevokedSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)
	setup.Revoke(session)

	_, err := test.callers().Resolve(test.request(setup.Credential(session)))

	Assert.IsTrue(test.rejected(err))
}

func (test *CallerServiceTest) TestResolveFailsClosedWhenTheEngineIsBusy() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)
	holder := setup.Open()
	defer holder.Close()
	setup.UseWait(200)

	_, err := test.callers().Resolve(test.request(setup.Credential(session)))

	var busy *host.EngineBusyError
	Assert.IsTrue(errors.As(err, &busy))
}

func (test *CallerServiceTest) TestRequireTenantAcceptsTheCallersTenant() {
	caller := Caller{TenantID: "tenant-a", PrincipalID: "principal-a", SessionID: "session-a"}

	Assert.IsTrue(test.callers().RequireTenant(caller, "tenant-a") == nil)
}

func (test *CallerServiceTest) TestRequireTenantRefusesAnotherTenant() {
	caller := Caller{TenantID: "tenant-a", PrincipalID: "principal-a", SessionID: "session-a"}

	err := test.callers().RequireTenant(caller, "tenant-b")

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
}

func (test *CallerServiceTest) TestRequireTenantRefusesAnEmptyTenant() {
	err := test.callers().RequireTenant(Caller{}, "")

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
}

func (test *CallerServiceTest) rejected(err error) bool {
	var rejected *host.SessionRejectedError
	return errors.As(err, &rejected)
}

func (test *CallerServiceTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *CallerServiceTest) callers() *CallerService {
	return &CallerService{engineService: &EngineService{engineSettingsService: &EngineSettingsService{}}}
}
