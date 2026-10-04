import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type FederationControllerTest struct {
	behaviors *BehaviorContext
}

func (test *FederationControllerTest) TestProviderRegisterAnswersTheDiscoveryFetchWithoutTheSecret() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()

	registration, err := controller.PostProviderRegister(test.request(setup, session), test.registerRequest(session.TenantID))

	Assert.IsTrue(err == nil)
	Assert.Equals(test.issuer()+"/.well-known/openid-configuration", registration.Fetch.URL)
	Assert.Equals("GET", registration.Fetch.Method)
	Assert.Equals("acme corp", registration.Provider.Name)
	Assert.IsTrue(!strings.Contains(test.encoded(registration), test.clientSecret()))
}

func (test *FederationControllerTest) TestProviderRegisterRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()

	_, err := controller.PostProviderRegister(test.request(setup, session), test.registerRequest(other.TenantID))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals(http.StatusForbidden, test.status(err))
}

func (test *FederationControllerTest) TestProviderRegisterRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()

	_, err := controller.PostProviderRegister(test.anonymous(), test.registerRequest(session.TenantID))

	Assert.Equals(http.StatusUnauthorized, test.status(err))
}

func (test *FederationControllerTest) TestProviderConfigureAcceptsDocumentsOnTheIssuersOrigin() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, session)
	key := test.signingKey()

	metadata, err := controller.PostProviderConfigure(test.request(setup, session), FederationProviderConfigureRequest{
		TenantID:          session.TenantID,
		ProviderID:        providerID,
		DiscoveryDocument: test.discovery(test.issuer()),
		KeySetDocument:    test.keySet(key),
	})

	Assert.IsTrue(err == nil)
	Assert.Equals(test.issuer()+"/token", metadata.TokenEndpoint)
	Assert.Equals(test.issuer()+"/jwks", metadata.KeySetURL)
}

func (test *FederationControllerTest) TestProviderConfigureRefusesAnEndpointOffTheIssuersOrigin() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, session)
	hostile := strings.ReplaceAll(test.discovery(test.issuer()), test.issuer()+"/token", "https://attacker.example/token")

	_, err := controller.PostProviderConfigure(test.request(setup, session), FederationProviderConfigureRequest{
		TenantID:          session.TenantID,
		ProviderID:        providerID,
		DiscoveryDocument: hostile,
		KeySetDocument:    test.keySet(test.signingKey()),
	})

	Assert.Equals(http.StatusBadRequest, test.status(err))
}

func (test *FederationControllerTest) TestProviderGetReportsTheConfigurationWithoutTheSecret() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.configured(controller, setup, session, test.signingKey())

	view, err := controller.PostProviderGet(test.request(setup, session), ProviderRequest{
		TenantID:   session.TenantID,
		ProviderID: providerID,
	})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(view.Configured)
	Assert.Equals(1, view.KeyCount)
	Assert.Equals(providerID, view.Provider.ProviderID)
	Assert.IsTrue(!strings.Contains(test.encoded(view), test.clientSecret()))
}

func (test *FederationControllerTest) TestProviderGetRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, other)

	_, err := controller.PostProviderGet(test.request(setup, session), ProviderRequest{
		TenantID:   other.TenantID,
		ProviderID: providerID,
	})

	Assert.Equals(http.StatusForbidden, test.status(err))
}

func (test *FederationControllerTest) TestProviderOfAnotherTenantIsNotFoundInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, other)

	_, err := controller.PostProviderDisable(test.request(setup, session), ProviderDisableRequest{
		TenantID:   session.TenantID,
		ProviderID: providerID,
	})

	Assert.Equals(http.StatusNotFound, test.status(err))
	Assert.Equals("provider_not_found", test.code(err))
	Assert.IsTrue(test.stillUsable(controller, setup, other, providerID))
}

func (test *FederationControllerTest) TestProviderDisableStopsNewLogins() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.configured(controller, setup, session, test.signingKey())

	outcome, err := controller.PostProviderDisable(test.request(setup, session), ProviderDisableRequest{
		TenantID:   session.TenantID,
		ProviderID: providerID,
		Reason:     "rotated away",
	})
	_, startErr := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(outcome.Disabled)
	Assert.Equals(http.StatusNotFound, test.status(startErr))
}

func (test *FederationControllerTest) TestNoRouteAnswersATokenRequest() {
	controllers := []any{&FederationController{}, &SamlController{}, &ScimController{}}

	Assert.IsTrue(!test.routesMethod(controllers, "PostLoginExchange"))
	Assert.Equals("", test.credentialField(controllers))
}

func (test *FederationControllerTest) controller() *FederationController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	calls := &TenantCallService{callerService: &CallerService{engineService: engine}, engineService: engine, administratorService: &AdministratorService{engineService: engine}, recentSignInService: &RecentSignInService{}}
	return &FederationController{engineService: engine, tenantCallService: calls}
}

func (test *FederationControllerTest) request(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := test.anonymous()
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *FederationControllerTest) anonymous() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}

func (test *FederationControllerTest) issuer() string {
	return "https://idp.example"
}

func (test *FederationControllerTest) clientSecret() string {
	return "provider-client-secret-value"
}

func (test *FederationControllerTest) registerRequest(tenantID string) FederationProviderRegisterRequest {
	return FederationProviderRegisterRequest{
		TenantID:     tenantID,
		Name:         "acme corp",
		Issuer:       test.issuer(),
		ClientID:     "sesame-client",
		ClientSecret: test.clientSecret(),
		Scopes:       []string{"email"},
		EmailClaim:   "email",
		Linking:      "verified_email",
	}
}

func (test *FederationControllerTest) registered(
	controller *FederationController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
) string {
	registration, err := controller.PostProviderRegister(test.request(setup, session), test.registerRequest(session.TenantID))
	test.check(err)
	return registration.Provider.ProviderID
}

func (test *FederationControllerTest) configured(
	controller *FederationController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	key *ecdsa.PrivateKey,
) string {
	providerID := test.registered(controller, setup, session)
	_, err := controller.PostProviderConfigure(test.request(setup, session), FederationProviderConfigureRequest{
		TenantID:          session.TenantID,
		ProviderID:        providerID,
		DiscoveryDocument: test.discovery(test.issuer()),
		KeySetDocument:    test.keySet(key),
	})
	test.check(err)
	return providerID
}

func (test *FederationControllerTest) stillUsable(
	controller *FederationController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	providerID string,
) bool {
	view, err := controller.PostProviderGet(test.request(setup, session), ProviderRequest{
		TenantID:   session.TenantID,
		ProviderID: providerID,
	})
	return err == nil && !view.Provider.Disabled
}

func (test *FederationControllerTest) startRequest(tenantID string, providerID string) FederationLoginStartRequest {
	return FederationLoginStartRequest{
		TenantID:    tenantID,
		ProviderID:  providerID,
		RedirectURI: "https://app.example/federation/callback",
	}
}

func (test *FederationControllerTest) discovery(issuer string) string {
	return test.encoded(map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
	})
}

func (test *FederationControllerTest) signingKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.check(err)
	return key
}

func (test *FederationControllerTest) keySet(key *ecdsa.PrivateKey) string {
	return test.encoded(map[string]any{"keys": []map[string]string{{
		"kty": "EC",
		"crv": "P-256",
		"kid": test.keyID(),
		"use": "sig",
		"alg": "ES256",
		"x":   test.coordinate(key.PublicKey.X.Bytes()),
		"y":   test.coordinate(key.PublicKey.Y.Bytes()),
	}}})
}

func (test *FederationControllerTest) keyID() string {
	return "signing-key"
}

func (test *FederationControllerTest) coordinate(value []byte) string {
	padded := make([]byte, 32)
	copy(padded[32-len(value):], value)
	return base64.RawURLEncoding.EncodeToString(padded)
}

func (test *FederationControllerTest) encoded(value any) string {
	encoded, err := json.Marshal(value)
	test.check(err)
	return string(encoded)
}

func (test *FederationControllerTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *FederationControllerTest) code(err error) string {
	var coded host.CodedError
	if !errors.As(err, &coded) {
		return ""
	}
	return coded.ErrorCode()
}

func (test *FederationControllerTest) routesMethod(controllers []any, name string) bool {
	for _, controller := range controllers {
		if _, found := reflect.TypeOf(controller).MethodByName(name); found {
			return true
		}
	}
	return false
}

func (test *FederationControllerTest) credentialField(controllers []any) string {
	for _, controller := range controllers {
		if field := test.credentialFieldOfRoutes(reflect.TypeOf(controller)); field != "" {
			return field
		}
	}
	return ""
}

func (test *FederationControllerTest) credentialFieldOfRoutes(controller reflect.Type) string {
	for index := 0; index < controller.NumMethod(); index++ {
		if field := test.credentialFieldOf(controller.Method(index).Type.Out(0)); field != "" {
			return controller.Method(index).Name + "." + field
		}
	}
	return ""
}

func (test *FederationControllerTest) credentialFieldOf(result reflect.Type) string {
	for result.Kind() == reflect.Slice || result.Kind() == reflect.Pointer {
		result = result.Elem()
	}
	if result.Kind() != reflect.Struct {
		return ""
	}
	return test.credentialFieldAmong(result)
}

func (test *FederationControllerTest) credentialFieldAmong(result reflect.Type) string {
	for index := 0; index < result.NumField(); index++ {
		name := strings.Split(result.Field(index).Tag.Get("json"), ",")[0]
		if test.isTokenRequestField(name) {
			return name
		}
		if nested := test.credentialFieldOf(result.Field(index).Type); nested != "" {
			return nested
		}
	}
	return ""
}

func (test *FederationControllerTest) isTokenRequestField(name string) bool {
	return name == "form" || name == "client_secret" || name == "code_verifier"
}

func (test *FederationControllerTest) check(err error) {
	if err != nil {
		panic(err)
	}
}
