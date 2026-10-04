import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type AdministratorRecentSignInTest struct {
	behaviors *BehaviorContext
}

func (test *AdministratorRecentSignInTest) TestStaleAdministratorCannotRegisterOrConfigureAnIdentityProvider() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := test.engine()
	request := test.request(setup, session)
	registration, registerFreshErr := test.federation(engine, 0).PostProviderRegister(request, test.federationProvider(session.TenantID))
	stale := test.federation(engine, test.staleAge())

	staleRegistration, registerErr := stale.PostProviderRegister(request, test.federationProvider(session.TenantID))
	_, configureErr := stale.PostProviderConfigure(request, FederationProviderConfigureRequest{
		TenantID:          session.TenantID,
		ProviderID:        registration.Provider.ProviderID,
		DiscoveryDocument: "{}",
		KeySetDocument:    "{}",
	})
	view, getErr := stale.PostProviderGet(request, ProviderRequest{TenantID: session.TenantID, ProviderID: registration.Provider.ProviderID})

	Assert.IsTrue(registerFreshErr == nil)
	Assert.Equals(http.StatusForbidden, test.status(registerErr))
	Assert.Equals(test.reauthentication(), test.answer(registerErr))
	Assert.Equals("", staleRegistration.Provider.ProviderID)
	Assert.Equals(test.reauthentication(), test.answer(configureErr))
	Assert.IsTrue(getErr == nil)
	Assert.IsTrue(view.Provider.ProviderID != "")
}

func (test *AdministratorRecentSignInTest) TestStaleAdministratorCannotRegisterASamlProvider() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)

	provider, err := test.saml(test.engine(), test.staleAge()).PostProviderRegister(
		test.request(setup, session),
		SamlProviderRegisterRequest{TenantID: session.TenantID, Name: "acme sso"},
	)

	Assert.Equals(http.StatusForbidden, test.status(err))
	Assert.Equals(test.reauthentication(), test.answer(err))
	Assert.Equals("", provider.ProviderID)
}

func (test *AdministratorRecentSignInTest) TestStaleAdministratorCannotMintAScimToken() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := test.engine()
	request := test.request(setup, session)
	registration, freshErr := test.scim(engine, 0).PostClientRegister(request, test.scimClient(session.TenantID))
	stale := test.scim(engine, test.staleAge())

	staleRegistration, registerErr := stale.PostClientRegister(request, test.scimClient(session.TenantID))
	rotated, rotateErr := stale.PostClientRotateToken(request, ScimClientRequest{
		TenantID:     session.TenantID,
		ScimClientID: registration.Client.ScimClientID,
	})
	_, listErr := stale.PostUserList(test.bearer(registration.Token), ScimListRequest{})

	Assert.IsTrue(freshErr == nil)
	Assert.Equals(http.StatusForbidden, test.status(registerErr))
	Assert.Equals(test.reauthentication(), test.answer(registerErr))
	Assert.Equals("", staleRegistration.Token)
	Assert.Equals(http.StatusForbidden, test.status(rotateErr))
	Assert.Equals(test.reauthentication(), test.answer(rotateErr))
	Assert.Equals("", rotated.Token)
	Assert.IsTrue(listErr == nil)
}

func (test *AdministratorRecentSignInTest) TestAdministratorInsideTheWindowMayRotateAScimToken() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := test.engine()
	request := test.request(setup, session)
	registration, registerErr := test.scim(engine, 0).PostClientRegister(request, test.scimClient(session.TenantID))

	rotated, err := test.scim(engine, 9*time.Minute).PostClientRotateToken(request, ScimClientRequest{
		TenantID:     session.TenantID,
		ScimClientID: registration.Client.ScimClientID,
	})

	Assert.IsTrue(registerErr == nil)
	Assert.IsTrue(err == nil)
	Assert.IsTrue(rotated.Token != "")
}

func (test *AdministratorRecentSignInTest) engine() *EngineService {
	return &EngineService{engineSettingsService: &EngineSettingsService{}}
}

func (test *AdministratorRecentSignInTest) federation(engine *EngineService, elapsed time.Duration) *FederationController {
	return &FederationController{
		engineService:         engine,
		engineSettingsService: engine.engineSettingsService,
		tenantCallService:     test.calls(engine, elapsed),
	}
}

func (test *AdministratorRecentSignInTest) saml(engine *EngineService, elapsed time.Duration) *SamlController {
	return &SamlController{
		engineService:         engine,
		engineSettingsService: engine.engineSettingsService,
		tenantCallService:     test.calls(engine, elapsed),
	}
}

func (test *AdministratorRecentSignInTest) scim(engine *EngineService, elapsed time.Duration) *ScimController {
	return &ScimController{
		engineService:     engine,
		tenantCallService: test.calls(engine, elapsed),
	}
}

func (test *AdministratorRecentSignInTest) calls(engine *EngineService, elapsed time.Duration) *TenantCallService {
	return &TenantCallService{
		callerService:        &CallerService{engineService: engine},
		engineService:        engine,
		administratorService: &AdministratorService{engineService: engine},
		recentSignInService:  &RecentSignInService{clockShift: elapsed},
	}
}

func (test *AdministratorRecentSignInTest) staleAge() time.Duration {
	return 11 * time.Minute
}

func (test *AdministratorRecentSignInTest) request(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *AdministratorRecentSignInTest) bearer(token string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func (test *AdministratorRecentSignInTest) federationProvider(tenantID string) FederationProviderRegisterRequest {
	return FederationProviderRegisterRequest{
		TenantID:     tenantID,
		Name:         "acme corp",
		Issuer:       "https://idp.example",
		ClientID:     "sesame-client",
		ClientSecret: "provider-client-secret-value",
		Scopes:       []string{"email"},
		EmailClaim:   "email",
		Linking:      "verified_email",
	}
}

func (test *AdministratorRecentSignInTest) scimClient(tenantID string) ScimClientRegisterRequest {
	return ScimClientRegisterRequest{TenantID: tenantID, Name: "directory", IdentifierNamespace: "email"}
}

func (test *AdministratorRecentSignInTest) reauthentication() string {
	return "reauthentication_required"
}

func (test *AdministratorRecentSignInTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *AdministratorRecentSignInTest) answer(err error) string {
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	test.check(readErr)
	problem := Problem{}
	test.check(json.Unmarshal(body, &problem))
	return problem.Code
}

func (test *AdministratorRecentSignInTest) check(err error) {
	if err != nil {
		panic(err)
	}
}
