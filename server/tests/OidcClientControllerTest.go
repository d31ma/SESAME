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
type OidcClientControllerTest struct {
	behaviors *BehaviorContext
}

func (test *OidcClientControllerTest) TestRegisterReturnsTheSecretInThatResponseOnly() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := test.engine()
	controller := test.controller(engine)
	request := test.request(setup.Credential(session))

	registered, err := controller.PostRegister(request, test.registration(session.TenantID, "confidential"))
	fetched, fetchErr := controller.PostGet(request, OidcClientReference{ClientID: registered.Client.ClientID})
	stored := json.RawMessage{}
	storedErr := engine.Call("oidc_client.get", OidcClientReference{ClientID: registered.Client.ClientID}, &stored)

	Assert.IsTrue(err == nil)
	Assert.IsTrue(len(registered.ClientSecret) > 0)
	Assert.Equals(session.TenantID, registered.Client.TenantID)
	Assert.IsTrue(fetchErr == nil)
	Assert.Equals("Portal", fetched.Name)
	Assert.IsTrue(!strings.Contains(test.encoded(fetched), registered.ClientSecret))
	Assert.IsTrue(storedErr == nil)
	Assert.IsTrue(!strings.Contains(string(stored), registered.ClientSecret))
}

func (test *OidcClientControllerTest) TestRegisterGivesAPublicClientNoSecret() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller(test.engine())

	registered, err := controller.PostRegister(test.request(setup.Credential(session)), test.registration(session.TenantID, "public"))

	Assert.IsTrue(err == nil)
	Assert.Equals("", registered.ClientSecret)
	Assert.Equals("public", registered.Client.ClientType)
}

func (test *OidcClientControllerTest) TestRegisterRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller(test.engine())

	registered, err := controller.PostRegister(test.request(setup.Credential(session)), test.registration(other.TenantID, "confidential"))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", registered.ClientSecret)
}

func (test *OidcClientControllerTest) TestRotateSecretReplacesTheSecretOnce() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := test.engine()
	controller := test.controller(engine)
	request := test.request(setup.Credential(session))
	registered, _ := controller.PostRegister(request, test.registration(session.TenantID, "confidential"))
	reference := OidcClientReference{ClientID: registered.Client.ClientID}

	rotated, err := controller.PostRotateSecret(request, reference)
	fetched, _ := controller.PostGet(request, reference)

	Assert.IsTrue(err == nil)
	Assert.IsTrue(len(rotated.ClientSecret) > 0)
	Assert.IsTrue(rotated.ClientSecret != registered.ClientSecret)
	Assert.IsTrue(!strings.Contains(test.encoded(fetched), rotated.ClientSecret))
	Assert.Equals("client_not_found", test.authenticationCode(engine, registered.Client.ClientID, registered.ClientSecret))
	Assert.Equals("", test.authenticationCode(engine, registered.Client.ClientID, rotated.ClientSecret))
}

func (test *OidcClientControllerTest) TestDisableStopsTheClient() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller(test.engine())
	request := test.request(setup.Credential(session))
	registered, _ := controller.PostRegister(request, test.registration(session.TenantID, "confidential"))

	disabled, err := controller.PostDisable(request, OidcClientDisableRequest{ClientID: registered.Client.ClientID, Reason: "retired"})
	fetched, _ := controller.PostGet(request, OidcClientReference{ClientID: registered.Client.ClientID})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(disabled.Disabled)
	Assert.IsTrue(fetched.Disabled)
}

func (test *OidcClientControllerTest) TestAnotherTenantsAdministratorCannotReachTheClient() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	engine := test.engine()
	controller := test.controller(engine)
	registered, _ := controller.PostRegister(test.request(setup.Credential(session)), test.registration(session.TenantID, "confidential"))
	reference := OidcClientReference{ClientID: registered.Client.ClientID}
	intruder := test.request(setup.Credential(other))

	fetched, getErr := controller.PostGet(intruder, reference)
	rotated, rotateErr := controller.PostRotateSecret(intruder, reference)
	_, disableErr := controller.PostDisable(intruder, OidcClientDisableRequest{ClientID: reference.ClientID})
	unchanged, _ := controller.PostGet(test.request(setup.Credential(session)), reference)

	Assert.IsTrue(test.mismatch(getErr))
	Assert.Equals("", fetched.Name)
	Assert.IsTrue(test.mismatch(rotateErr))
	Assert.Equals("", rotated.ClientSecret)
	Assert.IsTrue(test.mismatch(disableErr))
	Assert.IsTrue(!unchanged.Disabled)
	Assert.Equals("", test.authenticationCode(engine, registered.Client.ClientID, registered.ClientSecret))
}

func (test *OidcClientControllerTest) TestUnknownClientIsNotFound() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller(test.engine())

	_, err := controller.PostGet(test.request(setup.Credential(session)),
		OidcClientReference{ClientID: "cli_00000000000000000000000000000000"})

	Assert.Equals("client_not_found", test.protocolCode(err))
}

func (test *OidcClientControllerTest) TestAnonymousCallerIsRejected() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller(test.engine())
	anonymous := httptest.NewRequest(http.MethodPost, "/", nil)

	_, registerErr := controller.PostRegister(anonymous, test.registration(session.TenantID, "confidential"))
	_, getErr := controller.PostGet(anonymous, OidcClientReference{ClientID: "cli_00000000000000000000000000000000"})

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(registerErr, &rejected))
	Assert.IsTrue(errors.As(getErr, &rejected))
}

func (test *OidcClientControllerTest) authenticationCode(engine *EngineService, clientID string, secret string) string {
	err := engine.Call("oidc.introspect", map[string]string{
		"token": "not-a-token", "client_id": clientID, "client_secret": secret,
	}, &map[string]any{})
	return test.protocolCode(err)
}

func (test *OidcClientControllerTest) protocolCode(err error) string {
	protocolError := &sesame.ProtocolError{}
	errors.As(err, &protocolError)
	return protocolError.Code
}

func (test *OidcClientControllerTest) mismatch(err error) bool {
	var mismatch *host.TenantMismatchError
	return errors.As(err, &mismatch)
}

func (test *OidcClientControllerTest) registration(tenantID string, clientType string) OidcClientRegisterRequest {
	return OidcClientRegisterRequest{
		TenantID:   tenantID,
		Name:       "Portal",
		ClientType: clientType,
		Redirects:  []string{"https://rp.example/callback"},
		Scopes:     []string{"openid"},
		Audience:   "first_party",
	}
}

func (test *OidcClientControllerTest) encoded(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func (test *OidcClientControllerTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *OidcClientControllerTest) engine() *EngineService {
	return &EngineService{engineSettingsService: &EngineSettingsService{}}
}

func (test *OidcClientControllerTest) controller(engine *EngineService) *OidcClientController {
	callers := &CallerService{engineService: engine}
	return &OidcClientController{
		tenantCallService:   &TenantCallService{callerService: callers, engineService: engine},
		tenantRecordService: &TenantRecordService{callerService: callers, engineService: engine},
	}
}
