import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type SesameIdentityProviderTest struct {
	behaviors *BehaviorContext
}

func (test *SesameIdentityProviderTest) TestIdentifyWithoutACredentialIsAnonymous() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	identity, err := test.provider().Identify(httptest.NewRequest(http.MethodPost, "/", nil))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(identity == nil)
}

func (test *SesameIdentityProviderTest) TestIdentifyWithARejectedCredentialIsAnonymous() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)

	identity, err := test.provider().Identify(test.request(session.SessionID + ":not-the-secret"))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(identity == nil)
}

func (test *SesameIdentityProviderTest) TestIdentifyGivesAnAdministratorTheAdministratorRole() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)

	identity, err := test.provider().Identify(test.request(setup.Credential(session)))

	Assert.IsTrue(err == nil)
	Assert.Equals(session.PrincipalID, identity.User)
	Assert.Equals(1, len(identity.Roles))
	Assert.Equals("Administrator", identity.Roles[0])
}

func (test *SesameIdentityProviderTest) TestIdentifyGivesAMemberNoRoles() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)

	identity, err := test.provider().Identify(test.request(setup.Credential(session)))

	Assert.IsTrue(err == nil)
	Assert.Equals(session.PrincipalID, identity.User)
	Assert.Equals(0, len(identity.Roles))
}

func (test *SesameIdentityProviderTest) TestIdentifyFailsClosedWhenTheEngineIsBusy() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	holder := setup.Open()
	defer holder.Close()
	setup.UseWait(200)

	identity, err := test.provider().Identify(test.request(setup.Credential(session)))

	var busy *host.EngineBusyError
	Assert.IsTrue(errors.As(err, &busy))
	Assert.IsTrue(identity == nil)
}

func (test *SesameIdentityProviderTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *SesameIdentityProviderTest) provider() *SesameIdentityProvider {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &SesameIdentityProvider{
		callerService:        &CallerService{engineService: engine},
		administratorService: &AdministratorService{engineService: engine},
	}
}
