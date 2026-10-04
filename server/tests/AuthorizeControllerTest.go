import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type AuthorizeControllerTest struct {
	behaviors *BehaviorContext
}

func (test *AuthorizeControllerTest) TestDecideAllowsTheCallersGrantedPermission() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := test.engine()
	test.grantReader(engine, test.request(setup.Credential(administrator)), member)

	decision, err := test.controller(engine).PostDecide(test.request(setup.Credential(member)), test.question("file:a"))

	Assert.IsTrue(err == nil)
	Assert.Equals("allow", decision.Decision)
	Assert.Equals("allow_role_grant", decision.ReasonCode)
	Assert.IsTrue(decision.DecisionID != "")
}

func (test *AuthorizeControllerTest) TestDecideDeniesAPermissionTheCallerLacks() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := test.engine()
	test.grantReader(engine, test.request(setup.Credential(administrator)), member)

	decision, err := test.controller(engine).PostDecide(test.request(setup.Credential(member)), test.question("disk:a"))

	Assert.IsTrue(err == nil)
	Assert.Equals("deny", decision.Decision)
	Assert.Equals("deny_no_grant", decision.ReasonCode)
}

func (test *AuthorizeControllerTest) TestDecideAnswersForTheCallerNotTheAdministrator() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	question := AuthorizeDecideRequest{Action: "sesame:administer", Resource: "sesame:tenant"}

	decision, err := test.controller(test.engine()).PostDecide(test.request(setup.Credential(member)), question)

	Assert.IsTrue(err == nil)
	Assert.Equals("deny", decision.Decision)
}

func (test *AuthorizeControllerTest) TestDecideRefusesACallerAssertedSessionAttribute() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	question := test.question("file:a")
	question.Context = map[string]string{"session.assurance": "mfa"}

	_, err := test.controller(test.engine()).PostDecide(test.request(setup.Credential(member)), question)

	Assert.Equals("invalid_request", test.code(err))
}

func (test *AuthorizeControllerTest) TestDecideRefusesAStalePolicyVersion() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := test.engine()
	controller := test.controller(engine)
	first, _ := controller.PostDecide(test.request(setup.Credential(member)), test.question("file:a"))
	test.grantReader(engine, test.request(setup.Credential(administrator)), member)
	pinned := test.question("file:a")
	pinned.PolicyVersion = &first.PolicyVersion

	_, err := controller.PostDecide(test.request(setup.Credential(member)), pinned)

	Assert.Equals("stale_policy_version", test.code(err))
}

func (test *AuthorizeControllerTest) TestDecideRejectsARevokedSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	setup.Revoke(member)

	decision, err := test.controller(test.engine()).PostDecide(test.request(setup.Credential(member)), test.question("file:a"))

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
	Assert.Equals("", decision.Decision)
}

func (test *AuthorizeControllerTest) TestDecideRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()

	_, err := test.controller(test.engine()).PostDecide(httptest.NewRequest(http.MethodPost, "/", nil), test.question("file:a"))

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
}

func (test *AuthorizeControllerTest) TestDecideBodyCannotNameATenant() {
	body := `{"action":"doc:read","resource":"file:a","tenant_id":"tnt_00000000000000000000000000000000"}`

	err := test.decodeStrictly(body, &AuthorizeDecideRequest{})

	Assert.IsTrue(err != nil)
}

func (test *AuthorizeControllerTest) TestDecideBodyCannotNameAPrincipal() {
	body := `{"action":"doc:read","resource":"file:a","principal_id":"prn_00000000000000000000000000000000"}`

	err := test.decodeStrictly(body, &AuthorizeDecideRequest{})

	Assert.IsTrue(err != nil)
}

func (test *AuthorizeControllerTest) TestDecideBodyCannotNameASession() {
	body := `{"action":"doc:read","resource":"file:a","session_id":"ses_00000000000000000000000000000000","session_secret":"x"}`

	err := test.decodeStrictly(body, &AuthorizeDecideRequest{})

	Assert.IsTrue(err != nil)
}

func (test *AuthorizeControllerTest) TestDecideBatchQuestionCannotNameAPrincipal() {
	body := `{"requests":[{"action":"doc:read","resource":"file:a","principal_id":"prn_00000000000000000000000000000000"}]}`

	err := test.decodeStrictly(body, &AuthorizeDecideBatchRequest{})

	Assert.IsTrue(err != nil)
}

func (test *AuthorizeControllerTest) TestDecideBatchAnswersEveryQuestionUnderOneVersion() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := test.engine()
	test.grantReader(engine, test.request(setup.Credential(administrator)), member)
	batch := AuthorizeDecideBatchRequest{Requests: []AuthorizeQuestion{
		{Action: "doc:read", Resource: "file:a"},
		{Action: "doc:read", Resource: "disk:a"},
	}}

	answer, err := test.controller(engine).PostDecideBatch(test.request(setup.Credential(member)), batch)

	Assert.IsTrue(err == nil)
	Assert.Equals(2, len(answer.Decisions))
	Assert.Equals("allow", answer.Decisions[0].Decision)
	Assert.Equals("deny", answer.Decisions[1].Decision)
	Assert.Equals(answer.Decisions[0].PolicyVersion, answer.Decisions[1].PolicyVersion)
}

func (test *AuthorizeControllerTest) TestDecideBatchRefusesMoreThanOneHundredQuestions() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	batch := AuthorizeDecideBatchRequest{Requests: test.questions(101)}

	_, err := test.controller(test.engine()).PostDecideBatch(test.request(setup.Credential(administrator)), batch)

	Assert.Equals("invalid_request", test.code(err))
}

func (test *AuthorizeControllerTest) TestDecideBatchRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	batch := AuthorizeDecideBatchRequest{Requests: []AuthorizeQuestion{{Action: "doc:read", Resource: "file:a"}}}

	answer, err := test.controller(test.engine()).PostDecideBatch(httptest.NewRequest(http.MethodPost, "/", nil), batch)

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
	Assert.Equals(0, len(answer.Decisions))
}

func (test *AuthorizeControllerTest) grantReader(engine *EngineService, request *http.Request, member sesame.IssuedSession) {
	calls := test.tenantCalls(engine)
	role, err := (&RoleController{tenantCallService: calls}).PostCreate(request, RoleCreateRequest{
		TenantID:    member.TenantID,
		Name:        "reader",
		Permissions: []RolePermission{{Action: "doc:read", Resource: "file:*"}},
	})
	Assert.IsTrue(err == nil)
	_, err = (&GrantController{tenantCallService: calls}).PostCreate(request, GrantCreateRequest{
		TenantID:    member.TenantID,
		RoleID:      role.RoleID,
		PrincipalID: member.PrincipalID,
	})
	Assert.IsTrue(err == nil)
}

func (test *AuthorizeControllerTest) question(resource string) AuthorizeDecideRequest {
	return AuthorizeDecideRequest{Action: "doc:read", Resource: resource}
}

func (test *AuthorizeControllerTest) questions(count int) []AuthorizeQuestion {
	questions := make([]AuthorizeQuestion, 0, count)
	for range count {
		questions = append(questions, AuthorizeQuestion{Action: "doc:read", Resource: "file:a"})
	}
	return questions
}

func (test *AuthorizeControllerTest) decodeStrictly(body string, target any) error {
	decoder := json.NewDecoder(bytes.NewReader([]byte(body)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func (test *AuthorizeControllerTest) code(err error) string {
	protocolError := &sesame.ProtocolError{}
	errors.As(err, &protocolError)
	return protocolError.Code
}

func (test *AuthorizeControllerTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *AuthorizeControllerTest) engine() *EngineService {
	return &EngineService{engineSettingsService: &EngineSettingsService{}}
}

func (test *AuthorizeControllerTest) controller(engine *EngineService) *AuthorizeController {
	return &AuthorizeController{tenantCallService: test.tenantCalls(engine)}
}

func (test *AuthorizeControllerTest) tenantCalls(engine *EngineService) *TenantCallService {
	return &TenantCallService{
		callerService:        &CallerService{engineService: engine},
		engineService:        engine,
		administratorService: &AdministratorService{engineService: engine},
		recentSignInService:  &RecentSignInService{},
	}
}
