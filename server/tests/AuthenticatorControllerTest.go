import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type AuthenticatorControllerTest struct {
	behaviors *BehaviorContext
}

func (test *AuthenticatorControllerTest) TestSetPasswordReplacesOnlyTheCallersPassword() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session, oldPassword := test.signIn(setup)
	newPassword := rand.Text()
	controller := test.controller()
	authn := test.authn(controller)

	set, err := controller.PostSetPassword(test.request(setup, session), AuthenticatorPassword{Password: newPassword})
	oldLogin := test.loginWithPassword(authn, session, oldPassword)
	newLogin := test.loginWithPassword(authn, session, newPassword)

	Assert.IsTrue(err == nil)
	Assert.IsTrue(set.PasswordSet)
	Assert.Equals("", oldLogin.Assurance)
	Assert.Equals("password", newLogin.Assurance)
	Assert.IsTrue(!strings.Contains(test.json(set), newPassword))
}

func (test *AuthenticatorControllerTest) TestSetPasswordRefusesAShortPasswordWithoutEchoingIt() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session, _ := test.signIn(setup)
	short := "short-pw"

	_, err := test.controller().PostSetPassword(test.request(setup, session), AuthenticatorPassword{Password: short})

	Assert.Equals(http.StatusBadRequest, test.status(err))
	Assert.Equals(`{"code":"invalid_request"}`, test.answer(err))
}

func (test *AuthenticatorControllerTest) TestTotpEnrollmentLetsTheCallerReachMfaOnce() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session, password := test.signIn(setup)
	controller := test.controller()
	authn := test.authn(controller)
	request := test.request(setup, session)

	enrollment, enrollErr := controller.PostTotpEnroll(request, AuthenticatorTotpIssuer{})
	activation, activateErr := controller.PostTotpActivate(request, AuthenticatorTotpCode{Code: test.totp(enrollment.Secret, 0)})
	code := test.totp(enrollment.Secret, 1)
	first := test.loginWithPassword(authn, session, password)
	verified, verifyErr := authn.PostVerifyTotp(AuthnCodeRequest{TransactionID: first.TransactionID, Code: code})
	second := test.loginWithPassword(authn, session, password)
	replayed, replayErr := authn.PostVerifyTotp(AuthnCodeRequest{TransactionID: second.TransactionID, Code: code})

	Assert.IsTrue(enrollErr == nil)
	Assert.IsTrue(strings.HasPrefix(enrollment.ProvisioningURI, "otpauth://totp/"))
	Assert.IsTrue(activateErr == nil)
	Assert.IsTrue(activation.Activated)
	Assert.IsTrue(verifyErr == nil)
	Assert.Equals("mfa", verified.Assurance)
	Assert.IsTrue(replayErr == nil)
	Assert.Equals("password", replayed.Assurance)
	Assert.Equals(second.AttemptsLeft-1, replayed.AttemptsLeft)
}

func (test *AuthenticatorControllerTest) TestTotpActivateRefusesAWrongCode() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session, _ := test.signIn(setup)
	controller := test.controller()
	request := test.request(setup, session)
	enrollment, _ := controller.PostTotpEnroll(request, AuthenticatorTotpIssuer{Issuer: "Acme"})
	wrong := test.totp(enrollment.Secret, 10)

	activation, err := controller.PostTotpActivate(request, AuthenticatorTotpCode{Code: wrong})

	Assert.Equals(http.StatusBadRequest, test.status(err))
	Assert.IsTrue(!activation.Activated)
	Assert.IsTrue(!strings.Contains(test.answer(err), wrong))
}

func (test *AuthenticatorControllerTest) TestTotpEnrollRefusesToReplaceAnActiveFactor() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session, _ := test.signIn(setup)
	controller := test.controller()
	request := test.request(setup, session)
	enrollment, _ := controller.PostTotpEnroll(request, AuthenticatorTotpIssuer{})
	controller.PostTotpActivate(request, AuthenticatorTotpCode{Code: test.totp(enrollment.Secret, 0)})

	replacement, err := controller.PostTotpEnroll(request, AuthenticatorTotpIssuer{})

	Assert.Equals(http.StatusConflict, test.status(err))
	Assert.Equals("", replacement.Secret)
}

func (test *AuthenticatorControllerTest) TestRecoveryCodesAreSingleUseAndReissueRetiresThem() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session, password := test.signIn(setup)
	controller := test.controller()
	authn := test.authn(controller)
	request := test.request(setup, session)

	issued, err := controller.PostRecoveryCodesIssue(request)
	first := test.loginWithPassword(authn, session, password)
	used, usedErr := authn.PostVerifyRecoveryCode(AuthnCodeRequest{TransactionID: first.TransactionID, Code: issued.Codes[0]})
	second := test.loginWithPassword(authn, session, password)
	replayed, _ := authn.PostVerifyRecoveryCode(AuthnCodeRequest{TransactionID: second.TransactionID, Code: issued.Codes[0]})
	controller.PostRecoveryCodesIssue(request)
	third := test.loginWithPassword(authn, session, password)
	retired, _ := authn.PostVerifyRecoveryCode(AuthnCodeRequest{TransactionID: third.TransactionID, Code: issued.Codes[1]})

	Assert.IsTrue(err == nil)
	Assert.Equals(10, len(issued.Codes))
	Assert.IsTrue(usedErr == nil)
	Assert.Equals("mfa", used.Assurance)
	Assert.Equals("password", replayed.Assurance)
	Assert.Equals("password", retired.Assurance)
}

func (test *AuthenticatorControllerTest) TestEverySelfServiceRouteRefusesAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()
	anonymous := httptest.NewRequest(http.MethodPost, "/", nil)

	_, password := controller.PostSetPassword(anonymous, AuthenticatorPassword{Password: rand.Text()})
	_, enroll := controller.PostTotpEnroll(anonymous, AuthenticatorTotpIssuer{})
	_, activate := controller.PostTotpActivate(anonymous, AuthenticatorTotpCode{Code: "123456"})
	_, recovery := controller.PostRecoveryCodesIssue(anonymous)
	_, begin := controller.PostPasskeyRegisterBegin(anonymous)
	_, finish := controller.PostPasskeyRegisterFinish(anonymous, AuthenticatorPasskeyAttestation{})
	_, list := controller.PostPasskeyList(anonymous)
	_, remove := controller.PostPasskeyRemove(anonymous, AuthenticatorPasskeyRemoveRequest{CredentialID: "AAAA"})

	Assert.IsTrue(test.allAnswer(`{"code":"session_rejected"}`,
		[]error{password, enroll, activate, recovery, begin, finish, list, remove}))
}

func (test *AuthenticatorControllerTest) TestStaleSessionCannotChangeAnyAuthenticator() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session, password := test.signIn(setup)
	controller := test.controllerAfter(11 * time.Minute)
	request := test.request(setup, session)

	_, setErr := controller.PostSetPassword(request, AuthenticatorPassword{Password: rand.Text()})
	_, enrollErr := controller.PostTotpEnroll(request, AuthenticatorTotpIssuer{})
	_, activateErr := controller.PostTotpActivate(request, AuthenticatorTotpCode{Code: "123456"})
	_, recoveryErr := controller.PostRecoveryCodesIssue(request)
	_, beginErr := controller.PostPasskeyRegisterBegin(request)
	_, finishErr := controller.PostPasskeyRegisterFinish(request, AuthenticatorPasskeyAttestation{})
	_, removeErr := controller.PostPasskeyRemove(request, AuthenticatorPasskeyRemoveRequest{CredentialID: "AAAA"})
	listed, listErr := controller.PostPasskeyList(request)
	login := test.loginWithPassword(test.authn(controller), session, password)

	Assert.Equals(http.StatusForbidden, test.status(setErr))
	Assert.IsTrue(test.allAnswer(`{"code":"reauthentication_required"}`,
		[]error{setErr, enrollErr, activateErr, recoveryErr, beginErr, finishErr, removeErr}))
	Assert.IsTrue(listErr == nil)
	Assert.Equals(0, len(listed.Passkeys))
	Assert.Equals("password", login.Assurance)
}

func (test *AuthenticatorControllerTest) TestSessionInsideTheWindowMayChangeAuthenticators() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session, _ := test.signIn(setup)
	controller := test.controllerAfter(9 * time.Minute)

	set, err := controller.PostSetPassword(test.request(setup, session), AuthenticatorPassword{Password: rand.Text()})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(set.PasswordSet)
}

func (test *AuthenticatorControllerTest) TestAdministratorResetsAMembersPasswordWithAnOlderSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	password := rand.Text()
	controller := test.controllerAfter(11 * time.Minute)

	set, err := controller.PostSetPasswordForPrincipal(
		test.request(setup, administrator),
		AuthenticatorSetPasswordRequest{PrincipalID: member.PrincipalID, Password: password},
	)
	login := test.loginAs(test.authn(controller), AuthnBeginRequest{
		TenantID:            member.TenantID,
		IdentifierNamespace: "email",
		IdentifierValue:     "member@acme.test",
	}, password)

	Assert.IsTrue(err == nil)
	Assert.IsTrue(set.PasswordSet)
	Assert.Equals("password", login.Assurance)
}

func (test *AuthenticatorControllerTest) TestAdministratorCannotResetAPasswordInAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	stranger := setup.SignIn("globex", false)

	set, err := test.controller().PostSetPasswordForPrincipal(
		test.request(setup, administrator),
		AuthenticatorSetPasswordRequest{PrincipalID: stranger.PrincipalID, Password: rand.Text()},
	)

	Assert.Equals(http.StatusForbidden, test.status(err))
	Assert.Equals(`{"code":"tenant_mismatch"}`, test.answer(err))
	Assert.IsTrue(!set.PasswordSet)
}

func (test *AuthenticatorControllerTest) TestPasswordResetRefusesAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignIn("acme", false)

	_, err := test.controller().PostSetPasswordForPrincipal(
		httptest.NewRequest(http.MethodPost, "/", nil),
		AuthenticatorSetPasswordRequest{PrincipalID: member.PrincipalID, Password: rand.Text()},
	)

	Assert.Equals(`{"code":"session_rejected"}`, test.answer(err))
}

func (test *AuthenticatorControllerTest) signIn(setup *SesameTestSetup) (sesame.IssuedSession, string) {
	client := setup.Open()
	defer client.Close()
	ctx := context.Background()
	password := rand.Text()
	tenant, err := client.TenantBootstrap(ctx, "acme")
	test.check(err)
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", test.identifier())
	test.check(err)
	test.check(client.SetPassword(ctx, principal.ID, password))
	started, err := client.AuthenticationBegin(ctx, tenant.Tenant.ID, test.identifier())
	test.check(err)
	_, err = client.AuthenticationVerifyPassword(ctx, started.TransactionID, password)
	test.check(err)
	session, err := client.AuthenticationComplete(ctx, started.TransactionID, 0)
	test.check(err)
	return session, password
}

func (test *AuthenticatorControllerTest) loginWithPassword(
	authn *AuthnController,
	session sesame.IssuedSession,
	password string,
) AuthnTransaction {
	return test.loginAs(authn, AuthnBeginRequest{
		TenantID:            session.TenantID,
		IdentifierNamespace: test.identifier().Namespace,
		IdentifierValue:     test.identifier().Value,
	}, password)
}

func (test *AuthenticatorControllerTest) loginAs(authn *AuthnController, login AuthnBeginRequest, password string) AuthnTransaction {
	begun, err := authn.PostBegin(login)
	test.check(err)
	verified, err := authn.PostVerifyPassword(AuthnVerifyPasswordRequest{TransactionID: begun.TransactionID, Password: password})
	test.check(err)
	return verified
}

func (test *AuthenticatorControllerTest) identifier() sesame.PrincipalIdentifier {
	return sesame.PrincipalIdentifier{Namespace: "email", Value: "person@acme.test"}
}

func (test *AuthenticatorControllerTest) totp(secret string, stepsFromNow int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	test.check(err)
	counter := binary.BigEndian.AppendUint64(nil, uint64(time.Now().Unix()/30+stepsFromNow))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:])&0x7fffffff)%1000000)
}

func (test *AuthenticatorControllerTest) request(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *AuthenticatorControllerTest) allAnswer(answer string, failures []error) bool {
	for _, failure := range failures {
		if test.answer(failure) != answer {
			return false
		}
	}
	return true
}

func (test *AuthenticatorControllerTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *AuthenticatorControllerTest) answer(err error) string {
	body, _ := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	return string(body)
}

func (test *AuthenticatorControllerTest) json(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func (test *AuthenticatorControllerTest) check(err error) {
	if err != nil {
		panic(err)
	}
}

func (test *AuthenticatorControllerTest) controller() *AuthenticatorController {
	return test.controllerAfter(0)
}

func (test *AuthenticatorControllerTest) controllerAfter(elapsed time.Duration) *AuthenticatorController {
	engine := test.engine()
	return &AuthenticatorController{
		callerService:       &CallerService{engineService: engine},
		engineService:       engine,
		recentSignInService: &RecentSignInService{engineService: engine, clockShift: elapsed},
		principalTenantService: &PrincipalTenantService{
			callerService: &CallerService{engineService: engine},
			engineService: engine,
		},
	}
}

func (test *AuthenticatorControllerTest) authn(controller *AuthenticatorController) *AuthnController {
	return &AuthnController{engineService: controller.engineService}
}

func (test *AuthenticatorControllerTest) engine() *EngineService {
	return &EngineService{engineSettingsService: &EngineSettingsService{}}
}
