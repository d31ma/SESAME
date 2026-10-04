import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type OidcClientControllerTest struct {
	behaviors *BehaviorContext
}

func (test *OidcClientControllerTest) TestRegisterReturnsTheSecretInThatResponseOnly() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	controller := test.controller(engine)
	request := setup.SignedIn(session)

	registered, err := controller.PostRegister(request, test.registration(session.TenantID, "confidential"))
	fetched, fetchErr := controller.PostGet(request, OidcClientReference{ClientID: registered.Client.ClientID})
	stored := json.RawMessage{}
	storedErr := engine.Call("oidc_client.get", OidcClientReference{ClientID: registered.Client.ClientID}, &stored)

	Assert.IsTrue(err == nil)
	Assert.IsTrue(len(registered.ClientSecret) > 0)
	Assert.Equals(session.TenantID, registered.Client.TenantID)
	Assert.IsTrue(fetchErr == nil)
	Assert.Equals("Portal", fetched.Name)
	Assert.IsTrue(!strings.Contains(setup.Encoded(fetched), registered.ClientSecret))
	Assert.IsTrue(storedErr == nil)
	Assert.IsTrue(!strings.Contains(string(stored), registered.ClientSecret))
}

func (test *OidcClientControllerTest) TestRegisterGivesAPublicClientNoSecret() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller(setup.Engine())

	registered, err := controller.PostRegister(setup.SignedIn(session), test.registration(session.TenantID, "public"))

	Assert.IsTrue(err == nil)
	Assert.Equals("", registered.ClientSecret)
	Assert.Equals("public", registered.Client.ClientType)
}

func (test *OidcClientControllerTest) TestRegisterRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller(setup.Engine())

	registered, err := controller.PostRegister(setup.SignedIn(session), test.registration(other.TenantID, "confidential"))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", registered.ClientSecret)
}

func (test *OidcClientControllerTest) TestRotateSecretReplacesTheSecretOnce() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	controller := test.controller(engine)
	request := setup.SignedIn(session)
	registered, _ := controller.PostRegister(request, test.registration(session.TenantID, "confidential"))
	reference := OidcClientReference{ClientID: registered.Client.ClientID}

	rotated, err := controller.PostRotateSecret(request, reference)
	fetched, _ := controller.PostGet(request, reference)

	Assert.IsTrue(err == nil)
	Assert.IsTrue(len(rotated.ClientSecret) > 0)
	Assert.IsTrue(rotated.ClientSecret != registered.ClientSecret)
	Assert.IsTrue(!strings.Contains(setup.Encoded(fetched), rotated.ClientSecret))
	Assert.Equals("client_not_found", test.authenticationCode(engine, registered.Client.ClientID, registered.ClientSecret))
	Assert.Equals("", test.authenticationCode(engine, registered.Client.ClientID, rotated.ClientSecret))
}

func (test *OidcClientControllerTest) TestRotateSecretNeedsARecentSignIn() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	request := setup.SignedIn(session)
	registered, _ := test.controller(engine).PostRegister(request, test.registration(session.TenantID, "confidential"))

	rotated, err := test.controllerAfter(engine, 11*time.Minute).PostRotateSecret(request, OidcClientReference{ClientID: registered.Client.ClientID})

	Assert.IsTrue(setup.ReauthenticationRequired(err))
	Assert.Equals("", rotated.ClientSecret)
	Assert.Equals("", test.authenticationCode(engine, registered.Client.ClientID, registered.ClientSecret))
}

func (test *OidcClientControllerTest) TestRegisterNeedsARecentSignIn() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	request := setup.SignedIn(session)

	stale, staleErr := test.controllerAfter(engine, 11*time.Minute).PostRegister(request, test.registration(session.TenantID, "confidential"))
	registeredWhileStale := test.registrations(setup)
	fresh, freshErr := test.controller(engine).PostRegister(request, test.registration(session.TenantID, "confidential"))

	Assert.Equals(http.StatusForbidden, setup.Status(staleErr))
	Assert.IsTrue(setup.ReauthenticationRequired(staleErr))
	Assert.Equals("", stale.Client.ClientID)
	Assert.Equals("", stale.ClientSecret)
	Assert.Equals(0, registeredWhileStale)
	Assert.IsTrue(freshErr == nil)
	Assert.IsTrue(fresh.Client.ClientID != "")
	Assert.Equals(1, test.registrations(setup))
}

func (test *OidcClientControllerTest) TestDisableStopsTheClient() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller(setup.Engine())
	request := setup.SignedIn(session)
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
	engine := setup.Engine()
	controller := test.controller(engine)
	registered, _ := controller.PostRegister(setup.SignedIn(session), test.registration(session.TenantID, "confidential"))
	reference := OidcClientReference{ClientID: registered.Client.ClientID}
	intruder := setup.SignedIn(other)

	fetched, getErr := controller.PostGet(intruder, reference)
	rotated, rotateErr := controller.PostRotateSecret(intruder, reference)
	_, disableErr := controller.PostDisable(intruder, OidcClientDisableRequest{ClientID: reference.ClientID})
	unchanged, _ := controller.PostGet(setup.SignedIn(session), reference)

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
	controller := test.controller(setup.Engine())

	_, err := controller.PostGet(setup.SignedIn(session),
		OidcClientReference{ClientID: "cli_00000000000000000000000000000000"})

	Assert.Equals("client_not_found", setup.ProtocolCode(err))
}

func (test *OidcClientControllerTest) TestAnonymousCallerIsRejected() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller(setup.Engine())
	anonymous := httptest.NewRequest(http.MethodPost, "/", nil)

	_, registerErr := controller.PostRegister(anonymous, test.registration(session.TenantID, "confidential"))
	_, getErr := controller.PostGet(anonymous, OidcClientReference{ClientID: "cli_00000000000000000000000000000000"})

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(registerErr, &rejected))
	Assert.IsTrue(errors.As(getErr, &rejected))
}

func (test *OidcClientControllerTest) authenticationCode(engine *EngineHelper, clientID string, secret string) string {
	err := engine.Call("oidc.introspect", map[string]string{
		"token": "not-a-token", "client_id": clientID, "client_secret": secret,
	}, &map[string]any{})
	return SesameTestSetup{}.ProtocolCode(err)
}

func (test *OidcClientControllerTest) registrations(setup *SesameTestSetup) int {
	events := filepath.Join(setup.deployment, "fylo-root", ".collections", "sesame-security-events", "docs")
	count := 0
	_ = filepath.WalkDir(events, func(path string, entry os.DirEntry, err error) error {
		data, _ := os.ReadFile(path)
		count += strings.Count(string(data), "oidc_client.registered")
		return nil
	})
	return count
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

func (test *OidcClientControllerTest) controller(engine *EngineHelper) *OidcClientController {
	return test.controllerAfter(engine, 0)
}

func (test *OidcClientControllerTest) controllerAfter(engine *EngineHelper, elapsed time.Duration) *OidcClientController {
	return SesameTestSetup{}.OidcClients(engine, elapsed)
}
