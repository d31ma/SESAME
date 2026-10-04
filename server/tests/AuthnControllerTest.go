import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type AuthnControllerTest struct {
	behaviors *BehaviorContext
}

func (test *AuthnControllerTest) TestPasswordLoginIssuesAUsableSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, password := test.login(setup, "acme")
	controller := test.controller()

	begun, beginErr := controller.PostBegin(login)
	verified, verifyErr := controller.PostVerifyPassword(test.password(begun, password))
	session, err := controller.PostComplete(AuthnCompleteRequest{TransactionID: begun.TransactionID})

	Assert.IsTrue(beginErr == nil)
	Assert.IsTrue(verifyErr == nil)
	Assert.IsTrue(err == nil)
	Assert.Equals("awaiting_factor", begun.State)
	Assert.Equals("password", verified.Assurance)
	Assert.IsTrue(session.PrincipalID != "")
	Assert.Equals(login.TenantID, session.TenantID)
	Assert.IsTrue(session.SessionSecret != "")
	Assert.IsTrue(!strings.Contains(test.json(verified), password))
}

func (test *AuthnControllerTest) TestBeginAnswersTheSameForAnUnknownIdentifier() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, _ := test.login(setup, "acme")
	unknown := login
	unknown.IdentifierValue = "nobody@acme.test"
	controller := test.controller()

	known, knownErr := controller.PostBegin(login)
	stranger, err := controller.PostBegin(unknown)

	Assert.IsTrue(knownErr == nil)
	Assert.IsTrue(err == nil)
	Assert.Equals(known.State, stranger.State)
	Assert.Equals(known.AttemptsLeft, stranger.AttemptsLeft)
}

func (test *AuthnControllerTest) TestWrongPasswordSpendsAnAttemptAndEchoesNothing() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, password := test.login(setup, "acme")
	controller := test.controller()
	begun, _ := controller.PostBegin(login)
	wrong := password + "-wrong"

	verified, err := controller.PostVerifyPassword(test.password(begun, wrong))

	Assert.IsTrue(err == nil)
	Assert.Equals(begun.AttemptsLeft-1, verified.AttemptsLeft)
	Assert.Equals("", verified.Assurance)
	Assert.IsTrue(!strings.Contains(test.json(verified), wrong))
}

func (test *AuthnControllerTest) TestTransactionClosesAfterItsAttemptsAreSpent() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, password := test.login(setup, "acme")
	controller := test.controller()
	begun, _ := controller.PostBegin(login)
	wrong := test.password(begun, password+"-wrong")
	for attempt := 0; attempt < begun.AttemptsLeft; attempt++ {
		controller.PostVerifyPassword(wrong)
	}

	_, err := controller.PostVerifyPassword(test.password(begun, password))

	Assert.Equals(http.StatusConflict, test.status(err))
	Assert.Equals(`{"code":"transaction_closed"}`, test.answer(err))
}

func (test *AuthnControllerTest) TestCompleteBeforeAnyFactorIsRefused() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, _ := test.login(setup, "acme")
	controller := test.controller()
	begun, _ := controller.PostBegin(login)

	session, err := controller.PostComplete(AuthnCompleteRequest{TransactionID: begun.TransactionID})

	Assert.Equals(http.StatusConflict, test.status(err))
	Assert.Equals("", session.SessionSecret)
}

func (test *AuthnControllerTest) TestCompleteIsSingleUse() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, password := test.login(setup, "acme")
	controller := test.controller()
	begun, _ := controller.PostBegin(login)
	controller.PostVerifyPassword(test.password(begun, password))
	first, firstErr := controller.PostComplete(AuthnCompleteRequest{TransactionID: begun.TransactionID})

	replayed, err := controller.PostComplete(AuthnCompleteRequest{TransactionID: begun.TransactionID})

	Assert.IsTrue(firstErr == nil)
	Assert.IsTrue(first.SessionSecret != "")
	Assert.Equals(http.StatusConflict, test.status(err))
	Assert.Equals("", replayed.SessionSecret)
}

func (test *AuthnControllerTest) TestUnknownTransactionIsNotFound() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	password := "a password that is long enough"

	_, err := test.controller().PostVerifyPassword(AuthnVerifyPasswordRequest{
		TransactionID: "atx_00000000000000000000000000000000",
		Password:      password,
	})

	Assert.Equals(http.StatusNotFound, test.status(err))
	Assert.IsTrue(!strings.Contains(test.answer(err), password))
}

func (test *AuthnControllerTest) TestMalformedTransactionIsABadRequestThatEchoesNothing() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	password := "a password that is long enough"

	_, err := test.controller().PostVerifyPassword(AuthnVerifyPasswordRequest{TransactionID: "x", Password: password})

	Assert.Equals(http.StatusBadRequest, test.status(err))
	Assert.Equals(`{"code":"invalid_request"}`, test.answer(err))
}

func (test *AuthnControllerTest) TestTotpBeforeTheFirstFactorIsRefused() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, _ := test.login(setup, "acme")
	controller := test.controller()
	begun, _ := controller.PostBegin(login)

	verified, err := controller.PostVerifyTotp(AuthnCodeRequest{TransactionID: begun.TransactionID, Code: "123456"})

	Assert.Equals(http.StatusConflict, test.status(err))
	Assert.Equals("", verified.Assurance)
}

func (test *AuthnControllerTest) TestRecoveryCodeBeforeTheFirstFactorIsRefused() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, _ := test.login(setup, "acme")
	controller := test.controller()
	begun, _ := controller.PostBegin(login)
	code := "00000-00000-00000-00000"

	_, err := controller.PostVerifyRecoveryCode(AuthnCodeRequest{TransactionID: begun.TransactionID, Code: code})

	Assert.Equals(http.StatusConflict, test.status(err))
	Assert.IsTrue(!strings.Contains(test.answer(err), code))
}

func (test *AuthnControllerTest) TestPasskeyOptionsCarryAChallengeForEveryTransaction() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, _ := test.login(setup, "acme")
	controller := test.controller()
	begun, _ := controller.PostBegin(login)

	options, err := controller.PostPasskeyOptions(AuthnTransactionRequest{TransactionID: begun.TransactionID})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(options.Challenge != "")
	Assert.Equals(0, len(options.CredentialIDs))
}

func (test *AuthnControllerTest) TestUnknownPasskeyAssertionIsRejected() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	login, _ := test.login(setup, "acme")
	controller := test.controller()
	begun, _ := controller.PostBegin(login)

	verified, err := controller.PostVerifyPasskey(AuthnVerifyPasskeyRequest{
		TransactionID:     begun.TransactionID,
		CredentialID:      "AAAAAAAAAAAAAAAAAAAAAAAAAAA",
		AuthenticatorData: "AAAA",
		ClientDataJSON:    "AAAA",
		Signature:         "AAAA",
	})

	Assert.Equals(http.StatusBadRequest, test.status(err))
	Assert.Equals("", verified.Assurance)
}

func (test *AuthnControllerTest) login(setup *SesameTestSetup, tenantName string) (AuthnBeginRequest, string) {
	client := setup.Open()
	defer client.Close()
	ctx := context.Background()
	identifier := sesame.PrincipalIdentifier{Namespace: "email", Value: "person@" + tenantName + ".test"}
	password := rand.Text()
	tenant, err := client.TenantBootstrap(ctx, tenantName)
	test.check(err)
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	test.check(err)
	test.check(client.SetPassword(ctx, principal.ID, password))
	return AuthnBeginRequest{
		TenantID:            tenant.Tenant.ID,
		IdentifierNamespace: identifier.Namespace,
		IdentifierValue:     identifier.Value,
	}, password
}

func (test *AuthnControllerTest) check(err error) {
	if err != nil {
		panic(err)
	}
}

func (test *AuthnControllerTest) password(transaction AuthnTransaction, password string) AuthnVerifyPasswordRequest {
	return AuthnVerifyPasswordRequest{TransactionID: transaction.TransactionID, Password: password}
}

func (test *AuthnControllerTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *AuthnControllerTest) answer(err error) string {
	if err == nil {
		return ""
	}
	body, _ := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	return string(body)
}

func (test *AuthnControllerTest) json(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func (test *AuthnControllerTest) controller() *AuthnController {
	return &AuthnController{engineService: &EngineService{engineSettingsService: &EngineSettingsService{}}}
}
