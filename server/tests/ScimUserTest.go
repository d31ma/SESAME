import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type ScimUserTest struct {
	behaviors *BehaviorContext
}

func (test *ScimUserTest) TestUserCreateProvisionsWithTheBearerToken() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, false)

	user, err := controller.PostUserCreate(test.bearer(token), ScimResourceCreateRequest{Body: test.userBody("ada@acme.test")})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(user.ID != "")
	Assert.Equals("ada@acme.test", user.UserName)
	Assert.IsTrue(user.Active)
	Assert.IsTrue(!strings.Contains(test.encoded(user), token))
}

func (test *ScimUserTest) TestUserGetAndListFindTheUser() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, false)
	created := test.createdUser(controller, token, "ada@acme.test")

	user, err := controller.PostUserGet(test.bearer(token), ScimResourceRequest{ResourceID: created.ID})
	list, listErr := controller.PostUserList(test.bearer(token), ScimListRequest{Filter: `userName eq "ada@acme.test"`})

	Assert.IsTrue(err == nil)
	Assert.Equals(created.ID, user.ID)
	Assert.IsTrue(listErr == nil)
	Assert.Equals(1, list.TotalResults)
	Assert.Equals(created.ID, list.Resources[0].ID)
}

func (test *ScimUserTest) TestUserPatchReplacesTheDisplayName() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, false)
	created := test.createdUser(controller, token, "ada@acme.test")

	user, err := controller.PostUserPatch(test.bearer(token), ScimResourcePatchRequest{
		ResourceID: created.ID,
		Body:       test.patchBody("displayName", `"Ada Lovelace"`),
	})

	Assert.IsTrue(err == nil)
	Assert.Equals("Ada Lovelace", user.DisplayName)
}

func (test *ScimUserTest) TestUserDeprovisionDeactivatesTheUser() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, false)
	created := test.createdUser(controller, token, "ada@acme.test")

	outcome, err := controller.PostUserDeprovision(test.bearer(token), ScimResourceRequest{ResourceID: created.ID})
	user, getErr := controller.PostUserGet(test.bearer(token), ScimResourceRequest{ResourceID: created.ID})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(outcome.Deprovisioned)
	Assert.IsTrue(getErr == nil)
	Assert.IsTrue(!user.Active)
}

func (test *ScimUserTest) controller() *ScimController {
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

func (test *ScimUserTest) administrator(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := test.anonymous()
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *ScimUserTest) bearer(token string) *http.Request {
	request := test.anonymous()
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func (test *ScimUserTest) anonymous() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}

func (test *ScimUserTest) registerRequest(tenantID string, canManageGroups bool) ScimClientRegisterRequest {
	return ScimClientRegisterRequest{
		TenantID:            tenantID,
		Name:                "directory",
		IdentifierNamespace: "email",
		CanManageGroups:     canManageGroups,
	}
}

func (test *ScimUserTest) registeredClient(
	controller *ScimController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	canManageGroups bool,
) ScimClientRegistration {
	registration, err := controller.PostClientRegister(test.administrator(setup, session), test.registerRequest(session.TenantID, canManageGroups))
	test.check(err)
	return registration
}

func (test *ScimUserTest) clientToken(
	controller *ScimController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	canManageGroups bool,
) string {
	return test.registeredClient(controller, setup, session, canManageGroups).Token
}

func (test *ScimUserTest) createdUser(controller *ScimController, token string, userName string) ScimUser {
	user, err := controller.PostUserCreate(test.bearer(token), ScimResourceCreateRequest{Body: test.userBody(userName)})
	test.check(err)
	return user
}

func (test *ScimUserTest) userBody(userName string) string {
	return test.encoded(map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": userName,
	})
}

func (test *ScimUserTest) patchBody(path string, value string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
		`"Operations":[{"op":"replace","path":"` + path + `","value":` + value + `}]}`
}

func (test *ScimUserTest) encoded(value any) string {
	encoded, err := json.Marshal(value)
	test.check(err)
	return string(encoded)
}

func (test *ScimUserTest) check(err error) {
	if err != nil {
		panic(err)
	}
}
