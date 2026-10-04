import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
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
	Assert.IsTrue(!strings.Contains(setup.Encoded(session), issued.Secret))
}

func (test *SessionControllerTest) TestVerifyAnswersAWrongSecretLikeAnUnknownSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	issued := setup.SignIn("acme", false)
	controller := test.controller()
	wrong := issued.Secret + "x"

	_, wrongErr := controller.PostVerify(SessionCredential{SessionID: issued.SessionID, SessionSecret: wrong})
	_, unknownErr := controller.PostVerify(SessionCredential{SessionID: "ses_00000000000000000000000000000000", SessionSecret: wrong})

	Assert.Equals(http.StatusNotFound, setup.Status(wrongErr))
	Assert.Equals(test.answer(unknownErr), test.answer(wrongErr))
	Assert.IsTrue(!strings.Contains(test.answer(wrongErr), wrong))
}

func (test *SessionControllerTest) TestVerifyRefusesARevokedSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	issued := setup.SignIn("acme", false)
	setup.Revoke(issued)

	_, err := test.controller().PostVerify(SessionCredential{SessionID: issued.SessionID, SessionSecret: issued.Secret})

	Assert.Equals(http.StatusUnauthorized, setup.Status(err))
	Assert.Equals(`{"code":"session_inactive"}`, test.answer(err))
}

func (test *SessionControllerTest) TestVerifyRefusesAMalformedSessionID() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	secret := "a secret that must not be echoed"

	_, err := test.controller().PostVerify(SessionCredential{SessionID: "x", SessionSecret: secret})

	Assert.Equals(http.StatusBadRequest, setup.Status(err))
	Assert.IsTrue(!strings.Contains(test.answer(err), secret))
}

func (test *SessionControllerTest) TestRevokeEndsOnlyTheCallersSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	issued := setup.SignIn("acme", false)
	other := setup.SignIn("globex", false)

	revoking := test.controller()
	checking := test.controller()

	revocation, err := revoking.PostRevoke(setup.SignedIn(issued), SessionRevokeReason{Reason: "signed_out"})
	test.finish(revoking)
	_, revokedErr := checking.PostVerify(SessionCredential{SessionID: issued.SessionID, SessionSecret: issued.Secret})
	still, otherErr := checking.PostVerify(SessionCredential{SessionID: other.SessionID, SessionSecret: other.Secret})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(revocation.Revoked)
	Assert.Equals(http.StatusUnauthorized, setup.Status(revokedErr))
	Assert.IsTrue(otherErr == nil)
	Assert.Equals("active", still.Status)
}

func (test *SessionControllerTest) TestRevokeRefusesAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	revocation, err := test.controller().PostRevoke(httptest.NewRequest(http.MethodPost, "/", nil), SessionRevokeReason{})

	Assert.Equals(http.StatusUnauthorized, setup.Status(err))
	Assert.Equals(`{"code":"session_rejected"}`, test.answer(err))
	Assert.IsTrue(!revocation.Revoked)
}

func (test *SessionControllerTest) TestRevokeRefusesAnAlreadyRevokedCredential() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	issued := setup.SignIn("acme", false)
	setup.Revoke(issued)

	_, err := test.controller().PostRevoke(setup.SignedIn(issued), SessionRevokeReason{})

	Assert.Equals(http.StatusUnauthorized, setup.Status(err))
}

func (test *SessionControllerTest) TestRevokeByIDEndsASessionOfTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	revoking := test.controller()
	checking := test.controller()

	revocation, err := revoking.PostRevokeByID(setup.SignedIn(administrator), SessionRevokeRequest{SessionID: member.SessionID, Reason: "compromised"})
	test.finish(revoking)
	_, revokedErr := checking.PostVerify(SessionCredential{SessionID: member.SessionID, SessionSecret: member.Secret})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(revocation.Revoked)
	Assert.Equals(`{"code":"session_inactive"}`, test.answer(revokedErr))
}

func (test *SessionControllerTest) TestRevokeByIDDoesNotNeedARecentSignIn() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	revoking := &SessionController{engineService: engine, tenantCallService: setup.TenantCallsAfter(engine, 11*time.Minute)}

	revocation, err := revoking.PostRevokeByID(setup.SignedIn(administrator), SessionRevokeRequest{SessionID: member.SessionID, Reason: "compromised"})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(revocation.Revoked)
}

func (test *SessionControllerTest) TestRevokeByIDRefusesASessionOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignInMember("globex", "member")
	revoking := test.controller()
	checking := test.controller()

	revocation, err := revoking.PostRevokeByID(setup.SignedIn(administrator), SessionRevokeRequest{SessionID: other.SessionID})
	test.finish(revoking)
	still, otherErr := checking.PostVerify(SessionCredential{SessionID: other.SessionID, SessionSecret: other.Secret})

	Assert.Equals(http.StatusForbidden, setup.Status(err))
	Assert.Equals(`{"code":"actor_tenant_mismatch"}`, test.answer(err))
	Assert.IsTrue(!revocation.Revoked)
	Assert.IsTrue(otherErr == nil)
	Assert.Equals("active", still.Status)
}

func (test *SessionControllerTest) TestRevokeByIDAnswersARevokedSessionOfAnotherTenantLikeALiveOne() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignInMember("globex", "member")
	setup.Revoke(other)

	revocation, err := test.controller().PostRevokeByID(setup.SignedIn(administrator), SessionRevokeRequest{SessionID: other.SessionID})

	Assert.Equals(`{"code":"actor_tenant_mismatch"}`, test.answer(err))
	Assert.IsTrue(!revocation.Revoked)
}

func (test *SessionControllerTest) TestRevokeByIDAnswersNotFoundForAnUnknownSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	_, err := test.controller().PostRevokeByID(setup.SignedIn(administrator), SessionRevokeRequest{SessionID: "ses_00000000000000000000000000000000"})

	Assert.Equals(http.StatusNotFound, setup.Status(err))
}

func (test *SessionControllerTest) TestRevokeByIDRefusesAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignInMember("acme", "member")

	revocation, err := test.controller().PostRevokeByID(httptest.NewRequest(http.MethodPost, "/", nil), SessionRevokeRequest{SessionID: member.SessionID})

	Assert.Equals(`{"code":"session_rejected"}`, test.answer(err))
	Assert.IsTrue(!revocation.Revoked)
}

func (test *SessionControllerTest) answer(err error) string {
	body, _ := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	return string(body)
}

func (test *SessionControllerTest) finish(controller *SessionController) {
	if controller.engineService.client != nil {
		controller.engineService.client.Close()
	}
}

func (test *SessionControllerTest) controller() *SessionController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &SessionController{engineService: engine, tenantCallService: SesameTestSetup{}.TenantCalls(engine)}
}
