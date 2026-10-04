import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
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

func (test *SamlControllerTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *SamlControllerTest) check(err error) {
	if err != nil {
		panic(err)
	}
}
