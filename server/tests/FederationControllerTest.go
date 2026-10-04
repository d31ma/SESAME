import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"time"

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

func (test *FederationControllerTest) TestLoginStartAnswersOnlyWhatABrowserRedirectNeeds() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.configured(controller, setup, session, test.signingKey())

	login, err := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	Assert.IsTrue(err == nil)
	Assert.Equals(3, len(test.fields(login)))
	Assert.IsTrue(strings.HasPrefix(login.AuthorizationURL, test.issuer()+"/authorize?"))
	Assert.Equals("S256", test.query(login, "code_challenge_method"))
	Assert.Equals("", test.query(login, "code_verifier"))
	Assert.Equals("", test.query(login, "client_secret"))
	Assert.IsTrue(!strings.Contains(login.AuthorizationURL, test.clientSecret()))
}

func (test *FederationControllerTest) TestLoginCompleteIssuesAFederatedSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	key := test.signingKey()
	providerID := test.configured(controller, setup, session, key)
	login, startErr := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	result, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, key, test.query(login, "nonce")))

	Assert.IsTrue(startErr == nil)
	Assert.IsTrue(err == nil)
	Assert.IsTrue(result.Provisioned)
	Assert.Equals("federated", result.Session.Assurance)
	Assert.Equals(session.TenantID, result.Session.TenantID)
	Assert.IsTrue(result.Session.SessionSecret != "")
}

func (test *FederationControllerTest) TestLoginCompleteRefusesAReplayedLogin() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	key := test.signingKey()
	providerID := test.configured(controller, setup, session, key)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))
	request := test.completeRequest(session.TenantID, login, key, test.query(login, "nonce"))
	_, firstErr := controller.PostLoginComplete(request)

	replayed, err := controller.PostLoginComplete(request)

	Assert.IsTrue(firstErr == nil)
	Assert.Equals(http.StatusConflict, test.status(err))
	Assert.Equals("federated_login_closed", test.code(err))
	Assert.Equals("", replayed.Session.SessionSecret)
}

func (test *FederationControllerTest) TestLoginCompleteRejectsATokenForAnotherLogin() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	key := test.signingKey()
	providerID := test.configured(controller, setup, session, key)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, key, "another-nonce"))

	Assert.Equals(http.StatusBadRequest, test.status(err))
	Assert.Equals("assertion_rejected", test.answeredCode(err))
}

func (test *FederationControllerTest) TestLoginCompleteRejectsATokenSignedByAnotherKey() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.configured(controller, setup, session, test.signingKey())
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, test.signingKey(), test.query(login, "nonce")))

	Assert.Equals("assertion_rejected", test.answeredCode(err))
}

func (test *FederationControllerTest) TestLoginCompleteDoesNotFindAnotherTenantsLogin() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	key := test.signingKey()
	providerID := test.configured(controller, setup, session, key)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(other.TenantID, login, key, test.query(login, "nonce")))

	Assert.Equals(http.StatusNotFound, test.status(err))
}

func (test *FederationControllerTest) TestNoRouteAnswersATokenRequest() {
	controllers := []any{&FederationController{}, &SamlController{}, &ScimController{}}

	Assert.IsTrue(!test.routesMethod(controllers, "PostLoginExchange"))
	Assert.Equals("", test.credentialField(controllers))
}

func (test *FederationControllerTest) controller() *FederationController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	calls := &TenantCallService{callerService: &CallerService{engineService: engine}, engineService: engine}
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

func (test *FederationControllerTest) completeRequest(
	tenantID string,
	login FederationLogin,
	key *ecdsa.PrivateKey,
	nonce string,
) FederationLoginCompleteRequest {
	return FederationLoginCompleteRequest{
		TenantID: tenantID,
		LoginID:  login.LoginID,
		IDToken:  test.identityToken(key, nonce),
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

func (test *FederationControllerTest) identityToken(key *ecdsa.PrivateKey, nonce string) string {
	now := time.Now().Unix()
	header := test.segment(map[string]string{"alg": "ES256", "kid": test.keyID(), "typ": "JWT"})
	claims := test.segment(map[string]any{
		"iss":            test.issuer(),
		"sub":            "external-subject",
		"aud":            "sesame-client",
		"iat":            now,
		"exp":            now + 300,
		"nonce":          nonce,
		"email":          "ada@acme.test",
		"email_verified": true,
	})
	return header + "." + claims + "." + test.signature(key, header+"."+claims)
}

func (test *FederationControllerTest) segment(value any) string {
	return base64.RawURLEncoding.EncodeToString([]byte(test.encoded(value)))
}

func (test *FederationControllerTest) signature(key *ecdsa.PrivateKey, signed string) string {
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	test.check(err)
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (test *FederationControllerTest) query(login FederationLogin, name string) string {
	parsed, err := url.Parse(login.AuthorizationURL)
	test.check(err)
	return parsed.Query().Get(name)
}

func (test *FederationControllerTest) fields(value any) map[string]any {
	fields := map[string]any{}
	test.check(json.Unmarshal([]byte(test.encoded(value)), &fields))
	return fields
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

func (test *FederationControllerTest) answeredCode(err error) string {
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	test.check(readErr)
	problem := Problem{}
	test.check(json.Unmarshal(body, &problem))
	return problem.Code
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
