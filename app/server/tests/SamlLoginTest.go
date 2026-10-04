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
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/d31ma/sesame/app/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type SamlLoginTest struct {
	behaviors *BehaviorContext
}

func (test *SamlLoginTest) TestLoginStartAnswersOnlyWhatABrowserNeeds() {
	setup := test.provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, session, test.signer())

	login, err := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	Assert.IsTrue(err == nil)
	Assert.Equals(5, len(setup.Fields(login)))
	Assert.Equals(test.signOnURL(), login.Destination)
	Assert.IsTrue(strings.HasPrefix(login.RedirectURL, test.signOnURL()+"?"))
	Assert.Equals(login.LoginID, test.relayState(login))
	Assert.IsTrue(strings.Contains(login.AuthnRequest, test.consumerURL()))
}

func (test *SamlLoginTest) TestLoginCompleteIssuesASession() {
	setup := test.provision()
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

func (test *SamlLoginTest) TestLoginCompleteRefusesAReplayedResponse() {
	setup := test.provision()
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
	Assert.Equals(http.StatusNotFound, setup.Status(err))
	Assert.Equals("", replayed.Session.SessionSecret)
}

func (test *SamlLoginTest) TestLoginCompleteRefusesAnAssertionReplayedIntoANewLogin() {
	setup := test.provision()
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
	Assert.Equals(http.StatusBadRequest, setup.Status(err))
	Assert.Equals("saml_assertion_rejected", test.answeredCode(err))
}

func (test *SamlLoginTest) TestLoginCompleteRejectsAnAssertionForAnotherAudience() {
	setup := test.provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))
	assertion := strings.Replace(test.assertion(login), test.audience(), "https://other.example", 1)

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, signer, assertion))

	Assert.Equals(http.StatusBadRequest, setup.Status(err))
	Assert.Equals("saml_assertion_rejected", test.answeredCode(err))
}

func (test *SamlLoginTest) TestLoginCompleteRejectsAnExpiredAssertion() {
	setup := test.provision()
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

func (test *SamlLoginTest) TestLoginCompleteSpendsTheLoginOnARejection() {
	setup := test.provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))
	_, forgedErr := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, test.signer(), test.assertion(login)))

	_, err := controller.PostLoginComplete(test.completeRequest(session.TenantID, login, signer, test.assertion(login)))

	Assert.Equals("saml_assertion_rejected", test.answeredCode(forgedErr))
	Assert.Equals(http.StatusNotFound, setup.Status(err))
}

func (test *SamlLoginTest) TestLoginCompleteDoesNotFindAnotherTenantsLogin() {
	setup := test.provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	signer := test.signer()
	providerID := test.registered(controller, setup, session, signer)
	login, _ := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	_, err := controller.PostLoginComplete(test.completeRequest(other.TenantID, login, signer, test.assertion(login)))

	Assert.Equals(http.StatusNotFound, setup.Status(err))
	Assert.Equals("saml_login_not_found", test.answeredCode(err))
}

func (test *SamlLoginTest) controller() *SamlController {
	settings := &EngineSettingsService{}
	engine := &EngineService{engineSettingsService: settings}
	return &SamlController{
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

func (test *SamlLoginTest) entityID() string {
	return "https://idp.example/metadata"
}

func (test *SamlLoginTest) signOnURL() string {
	return "https://idp.example/sso"
}

func (test *SamlLoginTest) consumerURL() string {
	return "https://app.example/saml/acs"
}

func (test *SamlLoginTest) audience() string {
	return "https://sesame.test"
}

func (test *SamlLoginTest) registerRequest(tenantID string, signer *rsa.PrivateKey) SamlProviderRegisterRequest {
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

func (test *SamlLoginTest) registered(
	controller *SamlController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	signer *rsa.PrivateKey,
) string {
	provider, err := controller.PostProviderRegister(setup.SignedIn(session), test.registerRequest(session.TenantID, signer))
	setup.Check(err)
	return provider.ProviderID
}

func (test *SamlLoginTest) startRequest(tenantID string, providerID string) SamlLoginStartRequest {
	return SamlLoginStartRequest{TenantID: tenantID, ProviderID: providerID, ConsumerURL: test.consumerURL()}
}

func (test *SamlLoginTest) completeRequest(
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

func (test *SamlLoginTest) signer() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	SesameTestSetup{}.Check(err)
	return key
}

func (test *SamlLoginTest) certificate(key *rsa.PrivateKey) string {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	SesameTestSetup{}.Check(err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (test *SamlLoginTest) assertion(login SamlLogin) string {
	return test.assertionUntil(login, time.Now().Add(5*time.Minute))
}

func (test *SamlLoginTest) assertionUntil(login SamlLogin, expiresAt time.Time) string {
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

func (test *SamlLoginTest) instant(moment time.Time) string {
	return moment.UTC().Truncate(time.Minute).Format(time.RFC3339)
}

func (test *SamlLoginTest) signed(signer *rsa.PrivateKey, assertion string) string {
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
	SesameTestSetup{}.Check(err)
	element := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` + signedInfo +
		`<ds:SignatureValue>` + base64.StdEncoding.EncodeToString(signature) + `</ds:SignatureValue></ds:Signature>`
	return strings.Replace(assertion, `</saml:Issuer>`, `</saml:Issuer>`+element, 1)
}

func (test *SamlLoginTest) requestID(login SamlLogin) string {
	_, rest, _ := strings.Cut(login.AuthnRequest, ` ID="`)
	identifier, _, _ := strings.Cut(rest, `"`)
	return identifier
}

func (test *SamlLoginTest) relayState(login SamlLogin) string {
	parsed, err := url.Parse(login.RedirectURL)
	SesameTestSetup{}.Check(err)
	return parsed.Query().Get("RelayState")
}

func (test *SamlLoginTest) answeredCode(err error) string {
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	SesameTestSetup{}.Check(readErr)
	problem := Problem{}
	SesameTestSetup{}.Check(json.Unmarshal(body, &problem))
	return problem.Code
}

func (test *SamlLoginTest) provision() *SesameTestSetup {
	setup := SesameTestSetup{}.Provision()
	setup.UseSettings(map[string]any{
		"binary":           setup.binary,
		"deployment":       setup.deployment,
		"waitmilliseconds": 2000,
		"samlconsumerurls": []string{test.consumerURL()},
	})
	return setup
}
