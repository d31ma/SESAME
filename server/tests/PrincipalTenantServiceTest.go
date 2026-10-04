import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type PrincipalTenantServiceTest struct {
	behaviors *BehaviorContext
}

func (test *PrincipalTenantServiceTest) TestRequireReturnsAPrincipalOfTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")

	principal, err := test.service().Require(setup.SignedIn(administrator), member.PrincipalID)

	Assert.IsTrue(err == nil)
	Assert.Equals(member.PrincipalID, principal.PrincipalID)
	Assert.Equals(administrator.TenantID, principal.TenantID)
	Assert.Equals("member@acme.test", principal.Identifier.Value)
}

func (test *PrincipalTenantServiceTest) TestRequireRefusesAPrincipalOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)

	principal, err := test.service().Require(setup.SignedIn(administrator), other.PrincipalID)

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", principal.PrincipalID)
	Assert.Equals("", principal.TenantID)
}

func (test *PrincipalTenantServiceTest) TestRequireReportsAnUnknownPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	_, err := test.service().Require(setup.SignedIn(administrator), "prn_00000000000000000000000000000000")

	protocolError := &sesame.ProtocolError{}
	Assert.IsTrue(errors.As(err, &protocolError))
	Assert.Equals("principal_not_found", protocolError.Code)
}

func (test *PrincipalTenantServiceTest) TestRequireRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	principal, err := test.service().Require(httptest.NewRequest(http.MethodPost, "/", nil), administrator.PrincipalID)

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
	Assert.Equals("", principal.PrincipalID)
}

func (test *PrincipalTenantServiceTest) TestCallRunsTheOperationForAPrincipalOfTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	suspended := Principal{}

	err := test.service().Call(setup.SignedIn(administrator), member.PrincipalID, EngineCall{
		Operation:  "principal.suspend",
		Parameters: PrincipalReference{PrincipalID: member.PrincipalID},
		Result:     &suspended,
	})

	Assert.IsTrue(err == nil)
	Assert.Equals("suspended", suspended.Status)
}

func (test *PrincipalTenantServiceTest) TestCallRefusesAPrincipalOfAnotherTenantBeforeTheOperationRuns() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	service := test.service()
	suspended := Principal{}

	err := service.Call(setup.SignedIn(administrator), other.PrincipalID, EngineCall{
		Operation:  "principal.suspend",
		Parameters: PrincipalReference{PrincipalID: other.PrincipalID},
		Result:     &suspended,
	})
	untouched, check := service.Require(setup.SignedIn(other), other.PrincipalID)

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", suspended.Status)
	Assert.IsTrue(check == nil)
	Assert.Equals("active", untouched.Status)
}

func (test *PrincipalTenantServiceTest) service() *PrincipalTenantService {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &PrincipalTenantService{tenantCallService: SesameTestSetup{}.TenantCalls(engine)}
}
