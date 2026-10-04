import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
	"github.com/d31ma/sesame/app/server/packages/sesame"
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

	provider, err := controller.PostProviderRegister(setup.SignedIn(session), test.registerRequest(session.TenantID, test.signer()))

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

	_, err := controller.PostProviderRegister(setup.SignedIn(session), test.registerRequest(other.TenantID, test.signer()))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
}

func (test *SamlControllerTest) TestProviderRegisterRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()

	_, err := controller.PostProviderRegister(setup.Anonymous(), test.registerRequest(session.TenantID, test.signer()))

	Assert.Equals(http.StatusUnauthorized, setup.Status(err))
}

func (test *SamlControllerTest) TestProviderRegisterRefusesAnUnreadableCertificate() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	request := test.registerRequest(session.TenantID, test.signer())
	request.Certificates = []string{"not a certificate"}

	_, err := controller.PostProviderRegister(setup.SignedIn(session), request)

	Assert.Equals(http.StatusBadRequest, setup.Status(err))
}

func (test *SamlControllerTest) TestProviderGetReturnsTheProvider() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, session, test.signer())

	provider, err := controller.PostProviderGet(setup.SignedIn(session), ProviderRequest{
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

	_, err := controller.PostProviderDisable(setup.SignedIn(session), ProviderDisableRequest{
		TenantID:   session.TenantID,
		ProviderID: providerID,
	})
	provider, getErr := controller.PostProviderGet(setup.SignedIn(other), ProviderRequest{
		TenantID:   other.TenantID,
		ProviderID: providerID,
	})

	Assert.Equals(http.StatusNotFound, setup.Status(err))
	Assert.IsTrue(getErr == nil)
	Assert.IsTrue(!provider.Disabled)
}

func (test *SamlControllerTest) TestProviderDisableStopsNewLogins() {
	setup := test.provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	providerID := test.registered(controller, setup, session, test.signer())

	outcome, err := controller.PostProviderDisable(setup.SignedIn(session), ProviderDisableRequest{
		TenantID:   session.TenantID,
		ProviderID: providerID,
		Reason:     "certificate compromised",
	})
	_, startErr := controller.PostLoginStart(test.startRequest(session.TenantID, providerID))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(outcome.Disabled)
	Assert.Equals(providerID, outcome.ProviderID)
	Assert.Equals(http.StatusNotFound, setup.Status(startErr))
}

func (test *SamlControllerTest) controller() *SamlController {
	return SesameTestSetup{}.Saml(SesameTestSetup{}.Engine(), 0)
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
	provider, err := controller.PostProviderRegister(setup.SignedIn(session), test.registerRequest(session.TenantID, signer))
	setup.Check(err)
	return provider.ProviderID
}

func (test *SamlControllerTest) startRequest(tenantID string, providerID string) SamlLoginStartRequest {
	return SamlLoginStartRequest{TenantID: tenantID, ProviderID: providerID, ConsumerURL: test.consumerURL()}
}

func (test *SamlControllerTest) signer() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	SesameTestSetup{}.Check(err)
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
	SesameTestSetup{}.Check(err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (test *SamlControllerTest) provision() *SesameTestSetup {
	setup := SesameTestSetup{}.Provision()
	setup.UseSettings(map[string]any{
		"binary":           setup.binary,
		"deployment":       setup.deployment,
		"waitmilliseconds": 2000,
		"samlconsumerurls": []string{test.consumerURL()},
	})
	return setup
}
