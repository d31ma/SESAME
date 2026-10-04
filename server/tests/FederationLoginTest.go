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
type FederationLoginTest struct {
	behaviors *BehaviorContext
}

func (test *FederationLoginTest) TestLoginStartAnswersOnlyWhatABrowserRedirectNeeds() {
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

func (test *FederationLoginTest) TestLoginCompleteIssuesAFederatedSession() {
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

func (test *FederationLoginTest) TestLoginCompleteRefusesAReplayedLogin() {
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

func (test *FederationLoginTest) TestLoginCompleteRejectsATokenForAnotherLogin() {
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

func (test *FederationLoginTest) TestLoginCompleteRejectsATokenSignedByAnotherKey() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.configured(controller, setup, session, test.signingKey())
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, test.signingKey(), test.query(login, "nonce")))

	Assert.Equals("assertion_rejected", test.answeredCode(err))
}

func (test *FederationLoginTest) TestLoginCompleteDoesNotFindAnotherTenantsLogin() {
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

func (test *FederationLoginTest) controller() *FederationController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	calls := &TenantCallService{callerService: &CallerService{engineService: engine}, engineService: engine, administratorService: &AdministratorService{engineService: engine}, recentSignInService: &RecentSignInService{}}
	return &FederationController{engineService: engine, tenantCallService: calls}
}

func (test *FederationLoginTest) request(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := test.anonymous()
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *FederationLoginTest) anonymous() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}

func (test *FederationLoginTest) issuer() string {
	return "https://idp.example"
}

func (test *FederationLoginTest) clientSecret() string {
	return "provider-client-secret-value"
}

func (test *FederationLoginTest) registerRequest(tenantID string) FederationProviderRegisterRequest {
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

func (test *FederationLoginTest) registered(
	controller *FederationController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
) string {
	registration, err := controller.PostProviderRegister(test.request(setup, session), test.registerRequest(session.TenantID))
	test.check(err)
	return registration.Provider.ProviderID
}

func (test *FederationLoginTest) configured(
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

func (test *FederationLoginTest) startRequest(tenantID string, providerID string) FederationLoginStartRequest {
	return FederationLoginStartRequest{
		TenantID:    tenantID,
		ProviderID:  providerID,
		RedirectURI: "https://app.example/federation/callback",
	}
}

func (test *FederationLoginTest) completeRequest(
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

func (test *FederationLoginTest) discovery(issuer string) string {
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

func (test *FederationLoginTest) signingKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.check(err)
	return key
}

func (test *FederationLoginTest) keySet(key *ecdsa.PrivateKey) string {
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

func (test *FederationLoginTest) keyID() string {
	return "signing-key"
}

func (test *FederationLoginTest) coordinate(value []byte) string {
	padded := make([]byte, 32)
	copy(padded[32-len(value):], value)
	return base64.RawURLEncoding.EncodeToString(padded)
}

func (test *FederationLoginTest) identityToken(key *ecdsa.PrivateKey, nonce string) string {
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

func (test *FederationLoginTest) segment(value any) string {
	return base64.RawURLEncoding.EncodeToString([]byte(test.encoded(value)))
}

func (test *FederationLoginTest) signature(key *ecdsa.PrivateKey, signed string) string {
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	test.check(err)
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (test *FederationLoginTest) query(login FederationLogin, name string) string {
	parsed, err := url.Parse(login.AuthorizationURL)
	test.check(err)
	return parsed.Query().Get(name)
}

func (test *FederationLoginTest) fields(value any) map[string]any {
	fields := map[string]any{}
	test.check(json.Unmarshal([]byte(test.encoded(value)), &fields))
	return fields
}

func (test *FederationLoginTest) encoded(value any) string {
	encoded, err := json.Marshal(value)
	test.check(err)
	return string(encoded)
}

func (test *FederationLoginTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *FederationLoginTest) code(err error) string {
	var coded host.CodedError
	if !errors.As(err, &coded) {
		return ""
	}
	return coded.ErrorCode()
}

func (test *FederationLoginTest) answeredCode(err error) string {
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	test.check(readErr)
	problem := Problem{}
	test.check(json.Unmarshal(body, &problem))
	return problem.Code
}

func (test *FederationLoginTest) credentialFieldOf(result reflect.Type) string {
	for result.Kind() == reflect.Slice || result.Kind() == reflect.Pointer {
		result = result.Elem()
	}
	if result.Kind() != reflect.Struct {
		return ""
	}
	return test.credentialFieldAmong(result)
}

func (test *FederationLoginTest) credentialFieldAmong(result reflect.Type) string {
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

func (test *FederationLoginTest) isTokenRequestField(name string) bool {
	return name == "form" || name == "client_secret" || name == "code_verifier"
}

func (test *FederationLoginTest) check(err error) {
	if err != nil {
		panic(err)
	}
}
