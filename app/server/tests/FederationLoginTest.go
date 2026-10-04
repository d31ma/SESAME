import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type FederationLoginTest struct {
	behaviors *BehaviorContext
}

func (test *FederationLoginTest) TestLoginStartAnswersOnlyWhatABrowserRedirectNeeds() {
	setup := test.provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.configured(controller, setup, session, test.signingKey())

	login, err := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	Assert.IsTrue(err == nil)
	Assert.Equals(3, len(setup.Fields(login)))
	Assert.IsTrue(strings.HasPrefix(login.AuthorizationURL, test.issuer()+"/authorize?"))
	Assert.Equals("S256", test.query(login, "code_challenge_method"))
	Assert.Equals("", test.query(login, "code_verifier"))
	Assert.Equals("", test.query(login, "client_secret"))
	Assert.IsTrue(!strings.Contains(login.AuthorizationURL, test.clientSecret()))
}

func (test *FederationLoginTest) TestLoginCompleteIssuesAFederatedSession() {
	setup := test.provision()
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
	setup := test.provision()
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
	Assert.Equals(http.StatusConflict, setup.Status(err))
	Assert.Equals("federated_login_closed", setup.ErrorCode(err))
	Assert.Equals("", replayed.Session.SessionSecret)
}

func (test *FederationLoginTest) TestLoginCompleteRejectsATokenForAnotherLogin() {
	setup := test.provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	key := test.signingKey()
	providerID := test.configured(controller, setup, session, key)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, key, "another-nonce"))

	Assert.Equals(http.StatusBadRequest, setup.Status(err))
	Assert.Equals("assertion_rejected", test.answeredCode(err))
}

func (test *FederationLoginTest) TestLoginCompleteRejectsATokenSignedByAnotherKey() {
	setup := test.provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.configured(controller, setup, session, test.signingKey())
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, test.signingKey(), test.query(login, "nonce")))

	Assert.Equals("assertion_rejected", test.answeredCode(err))
}

func (test *FederationLoginTest) TestLoginCompleteDoesNotFindAnotherTenantsLogin() {
	setup := test.provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	key := test.signingKey()
	providerID := test.configured(controller, setup, session, key)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(other.TenantID, login, key, test.query(login, "nonce")))

	Assert.Equals(http.StatusNotFound, setup.Status(err))
}

func (test *FederationLoginTest) controller() *FederationController {
	settings := &EngineSettingsService{}
	engine := &EngineService{engineSettingsService: settings}
	return &FederationController{
		engineService:         engine,
		engineSettingsService: settings,
		tenantCallService: &TenantCallService{
			callerService:        &CallerService{engineService: engine},
			engineService:        engine,
			administratorService: &AdministratorService{engineService: engine},
			recentSignInService:  &RecentSignInService{},
		},
	}
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
	registration, err := controller.PostProviderRegister(setup.SignedIn(session), test.registerRequest(session.TenantID))
	setup.Check(err)
	return registration.Provider.ProviderID
}

func (test *FederationLoginTest) configured(
	controller *FederationController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	key *ecdsa.PrivateKey,
) string {
	providerID := test.registered(controller, setup, session)
	_, err := controller.PostProviderConfigure(setup.SignedIn(session), FederationProviderConfigureRequest{
		TenantID:          session.TenantID,
		ProviderID:        providerID,
		DiscoveryDocument: test.discovery(test.issuer()),
		KeySetDocument:    test.keySet(key),
	})
	setup.Check(err)
	return providerID
}

func (test *FederationLoginTest) startRequest(tenantID string, providerID string) FederationLoginStartRequest {
	return FederationLoginStartRequest{
		TenantID:    tenantID,
		ProviderID:  providerID,
		RedirectURI: test.redirectURI(),
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
	return SesameTestSetup{}.Encoded(map[string]any{
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
	SesameTestSetup{}.Check(err)
	return key
}

func (test *FederationLoginTest) keySet(key *ecdsa.PrivateKey) string {
	return SesameTestSetup{}.Encoded(map[string]any{"keys": []map[string]string{{
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
	header := SesameTestSetup{}.Segment(map[string]string{"alg": "ES256", "kid": test.keyID(), "typ": "JWT"})
	claims := SesameTestSetup{}.Segment(map[string]any{
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

func (test *FederationLoginTest) signature(key *ecdsa.PrivateKey, signed string) string {
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	SesameTestSetup{}.Check(err)
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (test *FederationLoginTest) query(login FederationLogin, name string) string {
	parsed, err := url.Parse(login.AuthorizationURL)
	SesameTestSetup{}.Check(err)
	return parsed.Query().Get(name)
}

func (test *FederationLoginTest) answeredCode(err error) string {
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	SesameTestSetup{}.Check(readErr)
	problem := Problem{}
	SesameTestSetup{}.Check(json.Unmarshal(body, &problem))
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

func (test *FederationLoginTest) provision() *SesameTestSetup {
	setup := SesameTestSetup{}.Provision()
	setup.UseSettings(map[string]any{
		"binary":                 setup.binary,
		"deployment":             setup.deployment,
		"waitmilliseconds":       2000,
		"federationredirecturis": []string{test.redirectURI()},
	})
	return setup
}

func (test *FederationLoginTest) redirectURI() string {
	return "https://app.example/federation/callback"
}
