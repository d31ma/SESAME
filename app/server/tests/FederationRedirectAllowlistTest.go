import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type FederationRedirectAllowlistTest struct {
	behaviors *BehaviorContext
}

func (test *FederationRedirectAllowlistTest) TestLoginStartRefusesAnAttackersRedirectURIWithoutStartingTheEngine() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	test.allow(setup, []string{test.redirectURI()})
	controller := test.controller()

	login, err := controller.PostLoginStart(test.startRequest("https://attacker.example/callback"))

	Assert.Equals(http.StatusBadRequest, setup.Status(err))
	Assert.IsTrue(setup.RedirectNotAllowed(err))
	Assert.Equals("", login.AuthorizationURL)
	Assert.IsTrue(controller.federatedLoginService.engineService.client == nil)
}

func (test *FederationRedirectAllowlistTest) TestLoginStartMatchesTheRedirectURIExactly() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	test.allow(setup, []string{test.redirectURI()})
	nearMisses := []string{
		test.redirectURI() + "/",
		test.redirectURI() + "?next=https://attacker.example",
		strings.ToUpper(test.redirectURI()),
		"",
	}

	Assert.IsTrue(test.allRefusedBeforeTheEngine(nearMisses))
}

func (test *FederationRedirectAllowlistTest) TestLoginStartRefusesEveryRedirectURIWhenNoneIsConfigured() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()

	_, err := controller.PostLoginStart(test.startRequest(test.redirectURI()))

	Assert.Equals(http.StatusBadRequest, setup.Status(err))
	Assert.IsTrue(setup.RedirectNotAllowed(err))
	Assert.IsTrue(controller.federatedLoginService.engineService.client == nil)
}

func (test *FederationRedirectAllowlistTest) TestSamlConsumerURLsDoNotAllowAFederationRedirect() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	setup.UseSettings(map[string]any{
		"binary":           setup.binary,
		"deployment":       setup.deployment,
		"samlconsumerurls": []string{test.redirectURI()},
	})
	controller := test.controller()

	_, err := controller.PostLoginStart(test.startRequest(test.redirectURI()))

	Assert.IsTrue(setup.RedirectNotAllowed(err))
}

func (test *FederationRedirectAllowlistTest) TestUnsafeRedirectURIConfigurationFailsClosed() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	unsafeEntries := []string{
		"http://app.example/federation/callback",
		"app.example/federation/callback",
		"https://app.example/federation/callback#",
		"",
	}

	Assert.IsTrue(test.allFailClosed(setup, unsafeEntries))
}

func (test *FederationRedirectAllowlistTest) allow(setup *SesameTestSetup, redirectURIs []string) {
	setup.UseSettings(map[string]any{
		"binary":                 setup.binary,
		"deployment":             setup.deployment,
		"waitmilliseconds":       2000,
		"federationredirecturis": redirectURIs,
	})
}

func (test *FederationRedirectAllowlistTest) controller() *FederationController {
	return SesameTestSetup{}.Federation(SesameTestSetup{}.Engine(), 0)
}

func (test *FederationRedirectAllowlistTest) redirectURI() string {
	return "https://app.example/federation/callback"
}

func (test *FederationRedirectAllowlistTest) startRequest(redirectURI string) FederationLoginStartRequest {
	return FederationLoginStartRequest{TenantID: "tenant", ProviderID: "provider", RedirectURI: redirectURI}
}

func (test *FederationRedirectAllowlistTest) allRefusedBeforeTheEngine(addresses []string) bool {
	refusals := []bool{}
	for _, address := range addresses {
		controller := test.controller()
		_, err := controller.PostLoginStart(test.startRequest(address))
		refusals = append(refusals, SesameTestSetup{}.RedirectNotAllowed(err) && controller.federatedLoginService.engineService.client == nil)
	}
	return !slices.Contains(refusals, false)
}

func (test *FederationRedirectAllowlistTest) allFailClosed(setup *SesameTestSetup, unsafeEntries []string) bool {
	refusals := []bool{}
	for _, entry := range unsafeEntries {
		test.allow(setup, []string{test.redirectURI(), entry})
		controller := test.controller()
		_, err := controller.PostLoginStart(test.startRequest(test.redirectURI()))
		var unconfigured *host.EngineNotConfiguredError
		refusals = append(refusals, errors.As(err, &unconfigured) && controller.federatedLoginService.engineService.client == nil)
	}
	return !slices.Contains(refusals, false)
}
