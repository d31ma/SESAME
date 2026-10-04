import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type SamlConsumerAllowlistTest struct {
	behaviors *BehaviorContext
}

func (test *SamlConsumerAllowlistTest) TestLoginStartRefusesAnAttackersConsumerURLWithoutStartingTheEngine() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	test.allow(setup, []string{test.consumerURL()})
	controller := test.controller()

	login, err := controller.PostLoginStart(test.startRequest("https://attacker.example/steal"))

	Assert.Equals(http.StatusBadRequest, setup.Status(err))
	Assert.IsTrue(setup.RedirectNotAllowed(err))
	Assert.Equals("", login.LoginID)
	Assert.IsTrue(controller.engineService.client == nil)
}

func (test *SamlConsumerAllowlistTest) TestLoginStartMatchesTheConsumerURLExactly() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	test.allow(setup, []string{test.consumerURL()})
	nearMisses := []string{
		test.consumerURL() + "/",
		test.consumerURL() + "?next=https://attacker.example",
		strings.ToUpper(test.consumerURL()),
		"",
	}

	Assert.IsTrue(test.allRefusedBeforeTheEngine(nearMisses))
}

func (test *SamlConsumerAllowlistTest) TestLoginStartRefusesEveryConsumerURLWhenNoneIsConfigured() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()

	_, err := controller.PostLoginStart(test.startRequest(test.consumerURL()))

	Assert.Equals(http.StatusBadRequest, setup.Status(err))
	Assert.IsTrue(setup.RedirectNotAllowed(err))
	Assert.IsTrue(controller.engineService.client == nil)
}

func (test *SamlConsumerAllowlistTest) TestLoginStartAcceptsAListedConsumerURL() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	test.allow(setup, []string{"https://other.example/acs", test.consumerURL()})
	session := setup.SignIn("acme", true)
	controller := test.controller()
	provider, registerErr := controller.PostProviderRegister(setup.SignedIn(session), test.registerRequest(session.TenantID))
	request := test.startRequest(test.consumerURL())
	request.TenantID = session.TenantID
	request.ProviderID = provider.ProviderID

	login, err := controller.PostLoginStart(request)

	Assert.IsTrue(registerErr == nil)
	Assert.IsTrue(err == nil)
	Assert.IsTrue(strings.Contains(login.AuthnRequest, test.consumerURL()))
}

func (test *SamlConsumerAllowlistTest) TestUnsafeConsumerURLConfigurationFailsClosed() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	unsafeEntries := []string{
		"http://app.example/saml/acs",
		"/saml/acs",
		"https://app.example/saml/acs#fragment",
		"https://",
		"",
	}

	Assert.IsTrue(test.allFailClosed(setup, unsafeEntries))
}

func (test *SamlConsumerAllowlistTest) allow(setup *SesameTestSetup, consumerURLs []string) {
	setup.UseSettings(map[string]any{
		"binary":           setup.binary,
		"deployment":       setup.deployment,
		"waitmilliseconds": 2000,
		"samlconsumerurls": consumerURLs,
	})
}

func (test *SamlConsumerAllowlistTest) controller() *SamlController {
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

func (test *SamlConsumerAllowlistTest) consumerURL() string {
	return "https://app.example/saml/acs"
}

func (test *SamlConsumerAllowlistTest) startRequest(consumerURL string) SamlLoginStartRequest {
	return SamlLoginStartRequest{TenantID: "tenant", ProviderID: "provider", ConsumerURL: consumerURL}
}

func (test *SamlConsumerAllowlistTest) registerRequest(tenantID string) SamlProviderRegisterRequest {
	return SamlProviderRegisterRequest{
		TenantID:            tenantID,
		Name:                "acme sso",
		EntityID:            "https://idp.example/metadata",
		SignOnURL:           "https://idp.example/sso",
		Certificates:        []string{test.certificate()},
		IdentifierNamespace: "email",
		Linking:             "verified_email",
	}
}

func (test *SamlConsumerAllowlistTest) certificate() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	SesameTestSetup{}.Check(err)
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

func (test *SamlConsumerAllowlistTest) allRefusedBeforeTheEngine(addresses []string) bool {
	refusals := []bool{}
	for _, address := range addresses {
		controller := test.controller()
		_, err := controller.PostLoginStart(test.startRequest(address))
		refusals = append(refusals, SesameTestSetup{}.RedirectNotAllowed(err) && controller.engineService.client == nil)
	}
	return !slices.Contains(refusals, false)
}

func (test *SamlConsumerAllowlistTest) allFailClosed(setup *SesameTestSetup, unsafeEntries []string) bool {
	refusals := []bool{}
	for _, entry := range unsafeEntries {
		test.allow(setup, []string{test.consumerURL(), entry})
		controller := test.controller()
		_, err := controller.PostLoginStart(test.startRequest(test.consumerURL()))
		var unconfigured *host.EngineNotConfiguredError
		refusals = append(refusals, errors.As(err, &unconfigured) && controller.engineService.client == nil)
	}
	return !slices.Contains(refusals, false)
}
