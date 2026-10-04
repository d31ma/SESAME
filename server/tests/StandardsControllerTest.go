import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type StandardsControllerTest struct {
	behaviors *BehaviorContext
}

func (test *StandardsControllerTest) TestDiscoveryPublishesTheHostRoutesUnderTheIssuer() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	response, err := test.controller().GetDiscovery(test.get("/oidc/openid-configuration"))

	metadata := test.object(response)
	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals("https://sesame.test", metadata["issuer"])
	Assert.Equals("https://sesame.test/oidc/authorize", metadata["authorization_endpoint"])
	Assert.Equals("https://sesame.test/oidc/token", metadata["token_endpoint"])
	Assert.Equals("https://sesame.test/oidc/jwks", metadata["jwks_uri"])
	Assert.Equals("https://sesame.test/oidc/introspect", metadata["introspection_endpoint"])
	Assert.Equals("https://sesame.test/oidc/revoke", metadata["revocation_endpoint"])
	Assert.Equals("https://sesame.test/oidc/logout", metadata["end_session_endpoint"])
}

func (test *StandardsControllerTest) TestJwksPublishesTheSigningKey() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	response, err := test.controller().GetJwks(test.get("/oidc/jwks"))

	keys, _ := test.object(response)["keys"].([]any)
	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals("application/json", response.Header.Get("Content-Type"))
	Assert.Equals(1, len(keys))
}

func (test *StandardsControllerTest) get(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, target, nil)
}

func (test *StandardsControllerTest) post(target string, form string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func (test *StandardsControllerTest) object(response *http.Response) map[string]any {
	decoded := map[string]any{}
	body, _ := io.ReadAll(response.Body)
	_ = json.Unmarshal(body, &decoded)
	return decoded
}

func (test *StandardsControllerTest) controller() *StandardsController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	refusals := &StandardsRefusalService{}
	return &StandardsController{
		standardsDispatchService: &StandardsDispatchService{engineService: engine, standardsRefusalService: refusals},
		standardsAnswerService: &StandardsAnswerService{
			standardsRefusalService:  refusals,
			interactionCookieService: &InteractionCookieService{},
		},
	}
}
