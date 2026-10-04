import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type SamlControllerTest struct {
	behaviors *BehaviorContext
}

func (test *SamlControllerTest) TestProviderRegisterReturnsTheProvider() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()

	provider, err := controller.PostProviderRegister(test.request(setup, session), test.registerRequest(session.TenantID, test.signer()))

	Assert.IsTrue(err == nil)
	Assert.Equals(session.TenantID, provider.TenantID)
	Assert.Equals(test.entityID(), provider.EntityID)
	Assert.Equals(test.signOnURL(), provider.SignOnURL)
	Assert.Equals(1, len(provider.Certificates))
}

func (test *SamlControllerTest) TestProviderRegisterRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()

	_, err := controller.PostProviderRegister(test.request(setup, session), test.registerRequest(other.TenantID, test.signer()))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
}

func (test *SamlControllerTest) TestProviderRegisterRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()

	_, err := controller.PostProviderRegister(test.anonymous(), test.registerRequest(session.TenantID, test.signer()))

	Assert.Equals(http.StatusUnauthorized, test.status(err))
}

func (test *SamlControllerTest) TestProviderRegisterRefusesAnUnreadableCertificate() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	request := test.registerRequest(session.TenantID, test.signer())
	request.Certificates = []string{"not a certificate"}

	_, err := controller.PostProviderRegister(test.request(setup, session), request)

	Assert.Equals(http.StatusBadRequest, test.status(err))
}

func (test *SamlControllerTest) TestProviderGetReturnsTheProvider() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, session, test.signer())

	provider, err := controller.PostProviderGet(test.request(setup, session), ProviderRequest{
		TenantID:   session.TenantID,
		ProviderID: providerID,
	})

	Assert.IsTrue(err == nil)
	Assert.Equals(providerID, provider.ProviderID)
	Assert.Equals("verified_email", provider.Linking)
}

func (test *SamlControllerTest) TestProviderOfAnotherTenantIsNotFoundInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, other, test.signer())

	_, err := controller.PostProviderDisable(test.request(setup, session), ProviderDisableRequest{
		TenantID:   session.TenantID,
		ProviderID: providerID,
	})
	provider, getErr := controller.PostProviderGet(test.request(setup, other), ProviderRequest{
		TenantID:   other.TenantID,
		ProviderID: providerID,
	})

	Assert.Equals(http.StatusNotFound, test.status(err))
	Assert.IsTrue(getErr == nil)
	Assert.IsTrue(!provider.Disabled)
}

func (test *SamlControllerTest) TestProviderDisableStopsNewLogins() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, session, test.signer())

	outcome, err := controller.PostProviderDisable(test.request(setup, session), ProviderDisableRequest{
		TenantID:   session.TenantID,
		ProviderID: providerID,
		Reason:     "certificate compromised",
	})
	_, startErr := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(outcome.Disabled)
	Assert.Equals(providerID, outcome.ProviderID)
	Assert.Equals(http.StatusNotFound, test.status(startErr))
}

func (test *SamlControllerTest) TestLoginStartAnswersOnlyWhatABrowserNeeds() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, session, test.signer())

	login, err := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	Assert.IsTrue(err == nil)
	Assert.Equals(5, len(test.fields(login)))
	Assert.Equals(test.signOnURL(), login.Destination)
	Assert.IsTrue(strings.HasPrefix(login.RedirectURL, test.signOnURL()+"?"))
	Assert.Equals(login.LoginID, test.relayState(login))
	Assert.IsTrue(strings.Contains(login.AuthnRequest, test.consumerURL()))
}

func (test *SamlControllerTest) TestLoginCompleteIssuesASession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	result, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, signer, test.assertion(login)))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(result.Provisioned)
	Assert.Equals(session.TenantID, result.Session.TenantID)
	Assert.IsTrue(result.Session.SessionSecret != "")
}

func (test *SamlControllerTest) TestLoginCompleteRefusesAReplayedResponse() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))
	request := test.completeRequest(session.TenantID, login, signer, test.assertion(login))
	_, firstErr := controller.PostLoginComplete(request)

	replayed, err := controller.PostLoginComplete(request)

	Assert.IsTrue(firstErr == nil)
	Assert.Equals(http.StatusNotFound, test.status(err))
	Assert.Equals("", replayed.Session.SessionSecret)
}

func (test *SamlControllerTest) TestLoginCompleteRefusesAnAssertionReplayedIntoANewLogin() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	first, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))
	_, firstErr := controller.PostLoginComplete(test.completeRequest(session.TenantID, first, signer, test.assertion(first)))
	second, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, second, signer, test.assertion(second)))

	Assert.IsTrue(firstErr == nil)
	Assert.Equals(http.StatusBadRequest, test.status(err))
	Assert.Equals("saml_assertion_rejected", test.answeredCode(err))
}

func (test *SamlControllerTest) TestLoginCompleteRejectsAnAssertionForAnotherAudience() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))
	assertion := strings.Replace(test.assertion(login), test.audience(), "https://other.example", 1)

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, signer, assertion))

	Assert.Equals(http.StatusBadRequest, test.status(err))
	Assert.Equals("saml_assertion_rejected", test.answeredCode(err))
}

func (test *SamlControllerTest) TestLoginCompleteRejectsAnExpiredAssertion() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))
	expired := test.assertionUntil(login, time.Now().Add(-5*time.Minute))

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, signer, expired))

	Assert.Equals("saml_assertion_rejected", test.answeredCode(err))
}

func (test *SamlControllerTest) TestLoginCompleteSpendsTheLoginOnARejection() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))
	_, forgedErr := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, test.signer(), test.assertion(login)))

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, signer, test.assertion(login)))

	Assert.Equals("saml_assertion_rejected", test.answeredCode(forgedErr))
	Assert.Equals(http.StatusNotFound, test.status(err))
}

func (test *SamlControllerTest) TestLoginCompleteDoesNotFindAnotherTenantsLogin() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(other.TenantID, login, signer, test.assertion(login)))

	Assert.Equals(http.StatusNotFound, test.status(err))
	Assert.Equals("saml_login_not_found", test.answeredCode(err))
}

func (test *SamlControllerTest) controller() *SamlController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	calls := &TenantCallService{callerService: &CallerService{engineService: engine}, engineService: engine}
	return &SamlController{engineService: engine, tenantCallService: calls}
}

func (test *SamlControllerTest) request(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := test.anonymous()
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *SamlControllerTest) anonymous() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}

func (test *SamlControllerTest) entityID() string {
	return "https://idp.example/metadata"
}

func (test *SamlControllerTest) signOnURL() string {
	return "https://idp.example/sso"
}

func (test *SamlControllerTest) consumerURL() string {
	return "https://app.example/saml/acs"
}

func (test *SamlControllerTest) audience() string {
	return "https://sesame.test"
}

func (test *SamlControllerTest) registerRequest(tenantID string, signer *rsa.PrivateKey) SamlProviderRegisterRequest {
	return SamlProviderRegisterRequest{
		TenantID:            tenantID,
		Name:                "acme sso",
		EntityID:            test.entityID(),
		SignOnURL:           test.signOnURL(),
		Certificates:        []string{test.certificate(signer)},
		IdentifierNamespace: "email",
		Linking:             "verified_email",
	}
}

func (test *SamlControllerTest) registered(
	controller *SamlController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	signer *rsa.PrivateKey,
) string {
	provider, err := controller.PostProviderRegister(test.request(setup, session), test.registerRequest(session.TenantID, signer))
	test.check(err)
	return provider.ProviderID
}

func (test *SamlControllerTest) startRequest(tenantID string, providerID string) SamlLoginStartRequest {
	return SamlLoginStartRequest{TenantID: tenantID, ProviderID: providerID, ConsumerURL: test.consumerURL()}
}

func (test *SamlControllerTest) completeRequest(
	tenantID string,
	login SamlLogin,
	signer *rsa.PrivateKey,
	assertion string,
) SamlLoginCompleteRequest {
	return SamlLoginCompleteRequest{
		TenantID:  tenantID,
		LoginID:   login.LoginID,
		Assertion: base64.StdEncoding.EncodeToString([]byte(test.signed(signer, assertion))),
	}
}

func (test *SamlControllerTest) signer() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	test.check(err)
	return key
}

func (test *SamlControllerTest) certificate(key *rsa.PrivateKey) string {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	test.check(err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (test *SamlControllerTest) assertion(login SamlLogin) string {
	return test.assertionUntil(login, time.Now().Add(5*time.Minute))
}

func (test *SamlControllerTest) assertionUntil(login SamlLogin, expiresAt time.Time) string {
	now := time.Now()
	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion-1" IssueInstant="` +
		test.instant(now.Add(-time.Minute)) + `" Version="2.0">` +
		`<saml:Issuer>` + test.entityID() + `</saml:Issuer>` +
		`<saml:Subject><saml:NameID>ada@acme.test</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<saml:SubjectConfirmationData InResponseTo="` + test.requestID(login) +
		`" Recipient="` + test.consumerURL() + `"></saml:SubjectConfirmationData>` +
		`</saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotBefore="` + test.instant(now.Add(-time.Minute)) +
		`" NotOnOrAfter="` + test.instant(expiresAt) + `">` +
		`<saml:AudienceRestriction><saml:Audience>` + test.audience() +
		`</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`</saml:Assertion>`
}

func (test *SamlControllerTest) instant(moment time.Time) string {
	return moment.UTC().Truncate(time.Minute).Format(time.RFC3339)
}

func (test *SamlControllerTest) signed(signer *rsa.PrivateKey, assertion string) string {
	digest := sha256.Sum256([]byte(assertion))
	signedInfo := `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>` +
		`<ds:Reference URI="#_assertion-1"><ds:Transforms>` +
		`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</ds:DigestValue>` +
		`</ds:Reference></ds:SignedInfo>`
	signedInfoDigest := sha256.Sum256([]byte(signedInfo))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, signedInfoDigest[:])
	test.check(err)
	element := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` + signedInfo +
		`<ds:SignatureValue>` + base64.StdEncoding.EncodeToString(signature) + `</ds:SignatureValue></ds:Signature>`
	return strings.Replace(assertion, `</saml:Issuer>`, `</saml:Issuer>`+element, 1)
}

func (test *SamlControllerTest) requestID(login SamlLogin) string {
	_, rest, _ := strings.Cut(login.AuthnRequest, ` ID="`)
	identifier, _, _ := strings.Cut(rest, `"`)
	return identifier
}

func (test *SamlControllerTest) relayState(login SamlLogin) string {
	parsed, err := url.Parse(login.RedirectURL)
	test.check(err)
	return parsed.Query().Get("RelayState")
}

func (test *SamlControllerTest) fields(value any) map[string]any {
	encoded, err := json.Marshal(value)
	test.check(err)
	fields := map[string]any{}
	test.check(json.Unmarshal(encoded, &fields))
	return fields
}

func (test *SamlControllerTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *SamlControllerTest) answeredCode(err error) string {
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	test.check(readErr)
	problem := Problem{}
	test.check(json.Unmarshal(body, &problem))
	return problem.Code
}

func (test *SamlControllerTest) check(err error) {
	if err != nil {
		panic(err)
	}
}
