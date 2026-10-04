import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type SesameErrorHandlerTest struct {
	behaviors *BehaviorContext
}

func (test *SesameErrorHandlerTest) TestBusyEngineAnswersServiceUnavailableWithRetryAfter() {
	response := test.answer(&host.EngineBusyError{})

	Assert.Equals(http.StatusServiceUnavailable, response.StatusCode)
	Assert.Equals("1", response.Header.Get("Retry-After"))
	Assert.Equals("engine_busy", test.code(response))
}

func (test *SesameErrorHandlerTest) TestRejectedSessionAnswersUnauthorized() {
	response := test.answer(&host.SessionRejectedError{})

	Assert.Equals(http.StatusUnauthorized, response.StatusCode)
	Assert.Equals("session_rejected", test.code(response))
}

func (test *SesameErrorHandlerTest) TestTenantMismatchAnswersForbidden() {
	response := test.answer(&host.TenantMismatchError{})

	Assert.Equals(http.StatusForbidden, response.StatusCode)
	Assert.Equals("tenant_mismatch", test.code(response))
}

func (test *SesameErrorHandlerTest) TestUnusableSettingsAnswerAnInternalError() {
	response := test.answer(&host.EngineNotConfiguredError{})

	Assert.Equals(http.StatusInternalServerError, response.StatusCode)
	Assert.Equals("internal_error", test.code(response))
}

func (test *SesameErrorHandlerTest) TestMissingRecordAnswersNotFound() {
	response := test.answer(test.engineError("principal_not_found"))

	Assert.Equals(http.StatusNotFound, response.StatusCode)
	Assert.Equals("principal_not_found", test.code(response))
}

func (test *SesameErrorHandlerTest) TestConflictAnswersConflict() {
	Assert.Equals(http.StatusConflict, test.answer(test.engineError("identifier_conflict")).StatusCode)
}

func (test *SesameErrorHandlerTest) TestInvalidRequestAnswersBadRequest() {
	Assert.Equals(http.StatusBadRequest, test.answer(test.engineError("invalid_request")).StatusCode)
}

func (test *SesameErrorHandlerTest) TestDeniedAnswersForbidden() {
	Assert.Equals(http.StatusForbidden, test.answer(test.engineError("access_denied")).StatusCode)
}

func (test *SesameErrorHandlerTest) TestInactiveSessionAnswersUnauthorized() {
	Assert.Equals(http.StatusUnauthorized, test.answer(test.engineError("session_inactive")).StatusCode)
}

func (test *SesameErrorHandlerTest) TestWrappedEngineErrorIsAnsweredByItsCode() {
	wrapped := fmt.Errorf("principal.get: %w", test.engineError("principal_not_found"))

	Assert.Equals(http.StatusNotFound, test.answer(wrapped).StatusCode)
}

func (test *SesameErrorHandlerTest) TestUnknownCodeFailsClosedWithoutTheCode() {
	response := test.answer(test.engineError("storage_not_configured"))

	Assert.Equals(http.StatusInternalServerError, response.StatusCode)
	Assert.Equals("internal_error", test.code(response))
}

func (test *SesameErrorHandlerTest) TestUncodedErrorFailsClosed() {
	response := test.answer(errors.New("read sesame response: EOF"))

	Assert.Equals(http.StatusInternalServerError, response.StatusCode)
	Assert.Equals("internal_error", test.code(response))
}

func (test *SesameErrorHandlerTest) TestAnswerNeverCarriesTheEngineMessage() {
	body, err := io.ReadAll(test.answer(test.engineError("principal_not_found")).Body)

	Assert.IsTrue(err == nil)
	Assert.IsTrue(!strings.Contains(string(body), "secret detail"))
}

func (test *SesameErrorHandlerTest) answer(failure error) *http.Response {
	return (&SesameErrorHandler{}).Answer(failure)
}

func (test *SesameErrorHandlerTest) engineError(code string) error {
	return &sesame.ProtocolError{Code: code, Message: "secret detail"}
}

func (test *SesameErrorHandlerTest) code(response *http.Response) string {
	Assert.Equals("application/json", response.Header.Get("Content-Type"))
	body, err := io.ReadAll(response.Body)
	Assert.IsTrue(err == nil)
	var problem Problem
	Assert.IsTrue(json.Unmarshal(body, &problem) == nil)
	return problem.Code
}
