import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type ScimBearerTest struct {
	behaviors *BehaviorContext
}

func (test *ScimBearerTest) TestResourceRouteWithoutABearerTokenAnswersUnauthorized() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()

	_, err := controller.PostUserList(test.anonymous(), ScimListRequest{})
	response := (&SesameErrorHandler{}).Answer(err)

	Assert.Equals(http.StatusUnauthorized, response.StatusCode)
	Assert.Equals("Bearer", response.Header.Get("WWW-Authenticate"))
	Assert.Equals("provisioning_denied", test.answeredCode(err))
}

func (test *ScimBearerTest) TestResourceRouteRefusesTheTokenUnderAnotherScheme() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, false)
	request := test.anonymous()
	request.Header.Set("Authorization", "Basic "+token)

	_, err := controller.PostUserList(request, ScimListRequest{})

	Assert.Equals(http.StatusUnauthorized, test.status(err))
}

func (test *ScimBearerTest) TestBearerSchemeIsCaseInsensitive() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, false)
	request := test.anonymous()
	request.Header.Set("Authorization", "bearer "+token)

	_, err := controller.PostUserList(request, ScimListRequest{})

	Assert.IsTrue(err == nil)
}

func (test *ScimBearerTest) TestRefusedTokenIsNeverEchoed() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	controller := test.controller()
	guessed := "guessed-provisioning-token-value"

	_, err := controller.PostUserCreate(test.bearer(guessed), ScimResourceCreateRequest{Body: test.userBody("ada@acme.test")})
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)

	Assert.IsTrue(readErr == nil)
	Assert.IsTrue(!strings.Contains(string(body), guessed))
	Assert.IsTrue(!strings.Contains(err.Error(), guessed))
}

func (test *ScimBearerTest) TestTokenSeesOnlyItsOwnTenantsUsers() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, false)
	otherToken := test.clientToken(controller, setup, other, false)
	created := test.createdUser(controller, token, "ada@acme.test")

	_, err := controller.PostUserGet(test.bearer(otherToken), ScimResourceRequest{ResourceID: created.ID})
	list, listErr := controller.PostUserList(test.bearer(otherToken), ScimListRequest{})

	Assert.Equals(http.StatusNotFound, test.status(err))
	Assert.IsTrue(listErr == nil)
	Assert.Equals(0, list.TotalResults)
}

func (test *ScimBearerTest) TestGroupRoutesNeedTheGroupGrant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, false)

	_, err := controller.PostGroupCreate(test.bearer(token), ScimResourceCreateRequest{Body: test.groupBody("engineering")})

	Assert.Equals(http.StatusForbidden, test.status(err))
	Assert.Equals("provisioning_forbidden", test.answeredCode(err))
}

func (test *ScimBearerTest) controller() *ScimController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &ScimController{
		engineService: engine,
		tenantCallService: &TenantCallService{
			callerService:        &CallerService{engineService: engine},
			engineService:        engine,
			administratorService: &AdministratorService{engineService: engine},
			recentSignInService:  &RecentSignInService{},
		},
	}
}

func (test *ScimBearerTest) administrator(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := test.anonymous()
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *ScimBearerTest) bearer(token string) *http.Request {
	request := test.anonymous()
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func (test *ScimBearerTest) anonymous() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}

func (test *ScimBearerTest) registerRequest(tenantID string, canManageGroups bool) ScimClientRegisterRequest {
	return ScimClientRegisterRequest{
		TenantID:            tenantID,
		Name:                "directory",
		IdentifierNamespace: "email",
		CanManageGroups:     canManageGroups,
	}
}

func (test *ScimBearerTest) registeredClient(
	controller *ScimController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	canManageGroups bool,
) ScimClientRegistration {
	registration, err := controller.PostClientRegister(test.administrator(setup, session), test.registerRequest(session.TenantID, canManageGroups))
	test.check(err)
	return registration
}

func (test *ScimBearerTest) clientToken(
	controller *ScimController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	canManageGroups bool,
) string {
	return test.registeredClient(controller, setup, session, canManageGroups).Token
}

func (test *ScimBearerTest) createdUser(controller *ScimController, token string, userName string) ScimUser {
	user, err := controller.PostUserCreate(test.bearer(token), ScimResourceCreateRequest{Body: test.userBody(userName)})
	test.check(err)
	return user
}

func (test *ScimBearerTest) userBody(userName string) string {
	return test.encoded(map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": userName,
	})
}

func (test *ScimBearerTest) groupBody(displayName string) string {
	return test.encoded(map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": displayName,
	})
}

func (test *ScimBearerTest) encoded(value any) string {
	encoded, err := json.Marshal(value)
	test.check(err)
	return string(encoded)
}

func (test *ScimBearerTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *ScimBearerTest) answeredCode(err error) string {
	body, readErr := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	test.check(readErr)
	problem := Problem{}
	test.check(json.Unmarshal(body, &problem))
	return problem.Code
}

func (test *ScimBearerTest) check(err error) {
	if err != nil {
		panic(err)
	}
}
