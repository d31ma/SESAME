import (
	"errors"
	"net/http"
	"strings"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type ScimControllerTest struct {
	behaviors *BehaviorContext
}

func (test *ScimControllerTest) TestClientRegisterReturnsTheTokenOnce() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()

	registration, err := controller.PostClientRegister(setup.SignedIn(session), setup.ScimRegisterRequest(session.TenantID, false))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(registration.Token != "")
	Assert.Equals(session.TenantID, registration.Client.TenantID)
	Assert.Equals("email", registration.Client.IdentifierNamespace)
	Assert.IsTrue(!strings.Contains(setup.Encoded(registration.Client), registration.Token))
}

func (test *ScimControllerTest) TestClientRegisterRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()

	_, err := controller.PostClientRegister(setup.SignedIn(session), setup.ScimRegisterRequest(other.TenantID, false))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
}

func (test *ScimControllerTest) TestClientRegisterRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()

	_, err := controller.PostClientRegister(setup.Anonymous(), setup.ScimRegisterRequest(session.TenantID, false))

	Assert.Equals(http.StatusUnauthorized, setup.Status(err))
}

func (test *ScimControllerTest) TestRotatedTokenReplacesThePreviousOne() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	registration := setup.ScimClient(controller, session, false)

	rotated, err := controller.PostClientRotateToken(setup.SignedIn(session), ScimClientRequest{
		TenantID:     session.TenantID,
		ScimClientID: registration.Client.ScimClientID,
	})
	_, oldErr := controller.PostUserList(setup.Bearer(registration.Token), ScimListRequest{})
	_, newErr := controller.PostUserList(setup.Bearer(rotated.Token), ScimListRequest{})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(rotated.Token != registration.Token)
	Assert.Equals(1, len(setup.Fields(rotated)))
	Assert.Equals(http.StatusUnauthorized, setup.Status(oldErr))
	Assert.IsTrue(newErr == nil)
}

func (test *ScimControllerTest) TestClientRotateTokenRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	registration := setup.ScimClient(controller, other, false)

	rotated, err := controller.PostClientRotateToken(setup.SignedIn(session), ScimClientRequest{
		TenantID:     other.TenantID,
		ScimClientID: registration.Client.ScimClientID,
	})

	Assert.Equals(http.StatusForbidden, setup.Status(err))
	Assert.Equals("", rotated.Token)
}

func (test *ScimControllerTest) TestDisabledClientIsRefused() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	registration := setup.ScimClient(controller, session, false)

	outcome, err := controller.PostClientDisable(setup.SignedIn(session), ScimClientDisableRequest{
		TenantID:     session.TenantID,
		ScimClientID: registration.Client.ScimClientID,
		Reason:       "directory retired",
	})
	_, listErr := controller.PostUserList(setup.Bearer(registration.Token), ScimListRequest{})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(outcome.Disabled)
	Assert.Equals(http.StatusUnauthorized, setup.Status(listErr))
}

func (test *ScimControllerTest) TestClientOfAnotherTenantIsNotFoundInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	registration := setup.ScimClient(controller, other, false)

	_, err := controller.PostClientDisable(setup.SignedIn(session), ScimClientDisableRequest{
		TenantID:     session.TenantID,
		ScimClientID: registration.Client.ScimClientID,
	})
	_, listErr := controller.PostUserList(setup.Bearer(registration.Token), ScimListRequest{})

	Assert.Equals(http.StatusNotFound, setup.Status(err))
	Assert.IsTrue(listErr == nil)
}

func (test *ScimControllerTest) controller() *ScimController {
	return SesameTestSetup{}.Scim(SesameTestSetup{}.Engine(), 0)
}
