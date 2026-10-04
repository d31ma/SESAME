import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type SessionControllerTest struct {
	behaviors *BehaviorContext
}

func (test *SessionControllerTest) TestVerifyDescribesTheSessionWithoutItsSecret() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	issued := setup.SignIn("acme", false)

	session, err := test.controller().PostVerify(SessionCredential{SessionID: issued.SessionID, SessionSecret: issued.Secret})

	Assert.IsTrue(err == nil)
	Assert.Equals(issued.SessionID, session.SessionID)
	Assert.Equals(issued.PrincipalID, session.PrincipalID)
	Assert.Equals(issued.TenantID, session.TenantID)
	Assert.Equals("active", session.Status)
	Assert.IsTrue(!strings.Contains(test.json(session), issued.Secret))
}

func (test *SessionControllerTest) TestVerifyAnswersAWrongSecretLikeAnUnknownSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	issued := setup.SignIn("acme", false)
	controller := test.controller()
	wrong := issued.Secret + "x"

	_, wrongErr := controller.PostVerify(SessionCredential{SessionID: issued.SessionID, SessionSecret: wrong})
	_, unknownErr := controller.PostVerify(SessionCredential{SessionID: "ses_00000000000000000000000000000000", SessionSecret: wrong})

	Assert.Equals(http.StatusNotFound, test.status(wrongErr))
	Assert.Equals(test.answer(unknownErr), test.answer(wrongErr))
	Assert.IsTrue(!strings.Contains(test.answer(wrongErr), wrong))
}

func (test *SessionControllerTest) TestVerifyRefusesARevokedSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	issued := setup.SignIn("acme", false)
	setup.Revoke(issued)

	_, err := test.controller().PostVerify(SessionCredential{SessionID: issued.SessionID, SessionSecret: issued.Secret})

	Assert.Equals(http.StatusUnauthorized, test.status(err))
	Assert.Equals(`{"code":"session_inactive"}`, test.answer(err))
}

func (test *SessionControllerTest) TestVerifyRefusesAMalformedSessionID() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	secret := "a secret that must not be echoed"

	_, err := test.controller().PostVerify(SessionCredential{SessionID: "x", SessionSecret: secret})

	Assert.Equals(http.StatusBadRequest, test.status(err))
	Assert.IsTrue(!strings.Contains(test.answer(err), secret))
}

func (test *SessionControllerTest) TestRevokeEndsOnlyTheCallersSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	issued := setup.SignIn("acme", false)
	other := setup.SignIn("globex", false)
	controller := test.controller()

	revocation, err := controller.PostRevoke(test.request(setup.Credential(issued)), SessionRevokeReason{Reason: "signed_out"})
	_, revokedErr := controller.PostVerify(SessionCredential{SessionID: issued.SessionID, SessionSecret: issued.Secret})
	still, otherErr := controller.PostVerify(SessionCredential{SessionID: other.SessionID, SessionSecret: other.Secret})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(revocation.Revoked)
	Assert.Equals(http.StatusUnauthorized, test.status(revokedErr))
	Assert.IsTrue(otherErr == nil)
	Assert.Equals("active", still.Status)
}

func (test *SessionControllerTest) TestRevokeRefusesAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	revocation, err := test.controller().PostRevoke(httptest.NewRequest(http.MethodPost, "/", nil), SessionRevokeReason{})

	Assert.Equals(http.StatusUnauthorized, test.status(err))
	Assert.Equals(`{"code":"session_rejected"}`, test.answer(err))
	Assert.IsTrue(!revocation.Revoked)
}

func (test *SessionControllerTest) TestRevokeRefusesAnAlreadyRevokedCredential() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	issued := setup.SignIn("acme", false)
	setup.Revoke(issued)

	_, err := test.controller().PostRevoke(test.request(setup.Credential(issued)), SessionRevokeReason{})

	Assert.Equals(http.StatusUnauthorized, test.status(err))
}

func (test *SessionControllerTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *SessionControllerTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *SessionControllerTest) answer(err error) string {
	body, _ := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	return string(body)
}

func (test *SessionControllerTest) json(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func (test *SessionControllerTest) controller() *SessionController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &SessionController{callerService: &CallerService{engineService: engine}, engineService: engine}
}
