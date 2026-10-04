import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type StandardsAnswerServiceTest struct {
	behaviors *BehaviorContext
}

func (test *StandardsAnswerServiceTest) TestAnswerServesAValidResponseAsItIs() {
	response, err := test.service().Answer(test.response(http.StatusOK, map[string]string{"cache-control": "no-store"}), nil)

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals("no-store", response.Header.Get("Cache-Control"))
	Assert.Equals(`{"active":false}`, test.text(response))
}

func (test *StandardsAnswerServiceTest) TestAnswerRefusesAHeaderOutsideTheAllowlist() {
	response, _ := test.service().Answer(test.response(http.StatusOK, map[string]string{"set-cookie": "a=b"}), nil)

	test.assertUnavailable(response)
}

func (test *StandardsAnswerServiceTest) TestAnswerRefusesALineBreakInAHeaderValue() {
	response, _ := test.service().Answer(test.response(http.StatusSeeOther,
		map[string]string{"location": "https://rp.example/\r\nSet-Cookie: a=b"}), nil)

	test.assertUnavailable(response)
}

func (test *StandardsAnswerServiceTest) TestAnswerRefusesAStatusOutsideTheContract() {
	response, _ := test.service().Answer(test.response(700, nil), nil)

	test.assertUnavailable(response)
}

func (test *StandardsAnswerServiceTest) TestAnswerRefusesAnUnsupportedContractVersion() {
	unsupported := test.response(http.StatusOK, nil)
	unsupported.ContractVersion = "2"

	response, _ := test.service().Answer(unsupported, nil)

	test.assertUnavailable(response)
}

func (test *StandardsAnswerServiceTest) TestAnswerRefusesAnInteractionOutsideTheAuthorizationEndpoint() {
	response, _ := test.service().Answer(test.interaction("interaction"), nil)

	test.assertUnavailable(response)
}

func (test *StandardsAnswerServiceTest) TestAuthorizeRefusesAnUnknownActionKind() {
	response, err := test.service().Authorize(test.interaction("redirect"), nil)

	Assert.IsTrue(err == nil)
	Assert.Equals(0, len(response.Cookies()))
	test.assertUnavailable(response)
}

func (test *StandardsAnswerServiceTest) TestAuthorizeServesAnOrdinaryRefusalWithoutACookie() {
	refusal := (&StandardsRefusalService{}).Refusal(http.StatusBadRequest, "invalid_request")

	response, err := test.service().Authorize(refusal, nil)

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusBadRequest, response.StatusCode)
	Assert.Equals(0, len(response.Cookies()))
	Assert.Equals(`{"error":"invalid_request"}`, test.text(response))
}

func (test *StandardsAnswerServiceTest) assertUnavailable(response *http.Response) {
	problem := StandardsProblem{}
	_ = json.Unmarshal([]byte(test.text(response)), &problem)
	Assert.Equals(http.StatusServiceUnavailable, response.StatusCode)
	Assert.Equals("server_error", problem.Error)
	Assert.Equals("no-store", response.Header.Get("Cache-Control"))
	Assert.Equals("", response.Header.Get("Location"))
	Assert.Equals("", response.Header.Get("Set-Cookie"))
}

func (test *StandardsAnswerServiceTest) response(status int, headers map[string]string) sesame.StandardsResponse {
	return sesame.StandardsResponse{
		ContractVersion: "1",
		Status:          status,
		Headers:         headers,
		Body:            json.RawMessage(`{"active":false}`),
	}
}

func (test *StandardsAnswerServiceTest) interaction(kind string) sesame.StandardsResponse {
	return sesame.StandardsResponse{
		ContractVersion: "1",
		Status:          http.StatusOK,
		Headers:         map[string]string{"cache-control": "no-store"},
		Action:          &sesame.StandardsInteraction{Kind: kind, InteractionID: "int_1", InteractionSecret: "secret"},
	}
}

func (test *StandardsAnswerServiceTest) text(response *http.Response) string {
	body, _ := io.ReadAll(response.Body)
	return string(body)
}

func (test *StandardsAnswerServiceTest) service() *StandardsAnswerService {
	return &StandardsAnswerService{
		standardsRefusalService:  &StandardsRefusalService{},
		interactionCookieService: &InteractionCookieService{},
	}
}
