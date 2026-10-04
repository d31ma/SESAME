import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
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

	registration, err := controller.PostClientRegister(test.administrator(setup, session), test.registerRequest(session.TenantID, false))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(registration.Token != "")
	Assert.Equals(session.TenantID, registration.Client.TenantID)
	Assert.Equals("email", registration.Client.IdentifierNamespace)
	Assert.IsTrue(!strings.Contains(test.encoded(registration.Client), registration.Token))
}

func (test *ScimControllerTest) TestClientRegisterRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()

	_, err := controller.PostClientRegister(test.administrator(setup, session), test.registerRequest(other.TenantID, false))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
}

func (test *ScimControllerTest) TestClientRegisterRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()

	_, err := controller.PostClientRegister(test.anonymous(), test.registerRequest(session.TenantID, false))

	Assert.Equals(http.StatusUnauthorized, test.status(err))
}

func (test *ScimControllerTest) TestRotatedTokenReplacesThePreviousOne() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	registration := test.registeredClient(controller, setup, session, false)

	rotated, err := controller.PostClientRotateToken(test.administrator(setup, session), ScimClientRequest{
		TenantID:     session.TenantID,
		ScimClientID: registration.Client.ScimClientID,
	})
	_, oldErr := controller.PostUserList(test.bearer(registration.Token), ScimListRequest{})
	_, newErr := controller.PostUserList(test.bearer(rotated.Token), ScimListRequest{})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(rotated.Token != registration.Token)
	Assert.Equals(1, len(test.fields(rotated)))
	Assert.Equals(http.StatusUnauthorized, test.status(oldErr))
	Assert.IsTrue(newErr == nil)
}

func (test *ScimControllerTest) TestClientRotateTokenRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	registration := test.registeredClient(controller, setup, other, false)

	rotated, err := controller.PostClientRotateToken(test.administrator(setup, session), ScimClientRequest{
		TenantID:     other.TenantID,
		ScimClientID: registration.Client.ScimClientID,
	})

	Assert.Equals(http.StatusForbidden, test.status(err))
	Assert.Equals("", rotated.Token)
}

func (test *ScimControllerTest) TestDisabledClientIsRefused() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	registration := test.registeredClient(controller, setup, session, false)

	outcome, err := controller.PostClientDisable(test.administrator(setup, session), ScimClientDisableRequest{
		TenantID:     session.TenantID,
		ScimClientID: registration.Client.ScimClientID,
		Reason:       "directory retired",
	})
	_, listErr := controller.PostUserList(test.bearer(registration.Token), ScimListRequest{})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(outcome.Disabled)
	Assert.Equals(http.StatusUnauthorized, test.status(listErr))
}

func (test *ScimControllerTest) TestClientOfAnotherTenantIsNotFoundInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	registration := test.registeredClient(controller, setup, other, false)

	_, err := controller.PostClientDisable(test.administrator(setup, session), ScimClientDisableRequest{
		TenantID:     session.TenantID,
		ScimClientID: registration.Client.ScimClientID,
	})
	_, listErr := controller.PostUserList(test.bearer(registration.Token), ScimListRequest{})

	Assert.Equals(http.StatusNotFound, test.status(err))
	Assert.IsTrue(listErr == nil)
}

func (test *ScimControllerTest) controller() *ScimController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &ScimController{
		engineService: engine,
		tenantCallService: &TenantCallService{
			callerService:        &CallerService{engineService: engine},
			engineService:        engine,
			administratorService: &AdministratorService{engineService: engine},
			recentSignInService:  &RecentSignInService{},
		},
	}
}

func (test *ScimControllerTest) administrator(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := test.anonymous()
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *ScimControllerTest) bearer(token string) *http.Request {
	request := test.anonymous()
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func (test *ScimControllerTest) anonymous() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}

func (test *ScimControllerTest) registerRequest(tenantID string, canManageGroups bool) ScimClientRegisterRequest {
	return ScimClientRegisterRequest{
		TenantID:            tenantID,
		Name:                "directory",
		IdentifierNamespace: "email",
		CanManageGroups:     canManageGroups,
	}
}

func (test *ScimControllerTest) registeredClient(
	controller *ScimController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	canManageGroups bool,
) ScimClientRegistration {
	registration, err := controller.PostClientRegister(test.administrator(setup, session), test.registerRequest(session.TenantID, canManageGroups))
	test.check(err)
	return registration
}

func (test *ScimControllerTest) fields(value any) map[string]any {
	fields := map[string]any{}
	test.check(json.Unmarshal([]byte(test.encoded(value)), &fields))
	return fields
}

func (test *ScimControllerTest) encoded(value any) string {
	encoded, err := json.Marshal(value)
	test.check(err)
	return string(encoded)
}

func (test *ScimControllerTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *ScimControllerTest) check(err error) {
	if err != nil {
		panic(err)
	}
}
