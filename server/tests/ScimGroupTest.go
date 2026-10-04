import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type ScimGroupTest struct {
	behaviors *BehaviorContext
}

func (test *ScimGroupTest) TestGroupCreateGetAndListFindTheGroup() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, true)

	created, err := controller.PostGroupCreate(test.bearer(token), ScimResourceCreateRequest{Body: test.groupBody("engineering")})
	group, getErr := controller.PostGroupGet(test.bearer(token), ScimResourceRequest{ResourceID: created.ID})
	list, listErr := controller.PostGroupList(test.bearer(token), ScimListRequest{})

	Assert.IsTrue(err == nil)
	Assert.Equals("engineering", created.DisplayName)
	Assert.IsTrue(getErr == nil)
	Assert.Equals(created.ID, group.ID)
	Assert.IsTrue(listErr == nil)
	Assert.Equals(1, list.TotalResults)
}

func (test *ScimGroupTest) TestGroupPatchAddsAMember() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, true)
	user := test.createdUser(controller, token, "ada@acme.test")
	created, createErr := controller.PostGroupCreate(test.bearer(token), ScimResourceCreateRequest{Body: test.groupBody("engineering")})

	group, err := controller.PostGroupPatch(test.bearer(token), ScimResourcePatchRequest{
		ResourceID: created.ID,
		Body:       test.memberPatchBody(user.ID),
	})

	Assert.IsTrue(createErr == nil)
	Assert.IsTrue(err == nil)
	Assert.Equals(1, len(group.Members))
	Assert.Equals(user.ID, group.Members[0])
}

func (test *ScimGroupTest) TestGroupDeprovisionRemovesEveryMemberAndKeepsTheGroupReadable() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := test.clientToken(controller, setup, session, true)
	user := test.createdUser(controller, token, "ada@acme.test")
	created, createErr := controller.PostGroupCreate(test.bearer(token), ScimResourceCreateRequest{Body: test.groupBody("engineering")})
	_, patchErr := controller.PostGroupPatch(test.bearer(token), ScimResourcePatchRequest{
		ResourceID: created.ID,
		Body:       test.memberPatchBody(user.ID),
	})

	outcome, err := controller.PostGroupDeprovision(test.bearer(token), ScimResourceRequest{ResourceID: created.ID})
	group, getErr := controller.PostGroupGet(test.bearer(token), ScimResourceRequest{ResourceID: created.ID})

	Assert.IsTrue(createErr == nil)
	Assert.IsTrue(patchErr == nil)
	Assert.IsTrue(err == nil)
	Assert.IsTrue(outcome.Deprovisioned)
	Assert.IsTrue(getErr == nil)
	Assert.Equals(0, len(group.Members))
}

func (test *ScimGroupTest) controller() *ScimController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	calls := &TenantCallService{callerService: &CallerService{engineService: engine}, engineService: engine}
	return &ScimController{engineService: engine, tenantCallService: calls}
}

func (test *ScimGroupTest) administrator(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := test.anonymous()
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *ScimGroupTest) bearer(token string) *http.Request {
	request := test.anonymous()
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func (test *ScimGroupTest) anonymous() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}

func (test *ScimGroupTest) registerRequest(tenantID string, canManageGroups bool) ScimClientRegisterRequest {
	return ScimClientRegisterRequest{
		TenantID:            tenantID,
		Name:                "directory",
		IdentifierNamespace: "email",
		CanManageGroups:     canManageGroups,
	}
}

func (test *ScimGroupTest) registeredClient(
	controller *ScimController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	canManageGroups bool,
) ScimClientRegistration {
	registration, err := controller.PostClientRegister(test.administrator(setup, session), test.registerRequest(session.TenantID, canManageGroups))
	test.check(err)
	return registration
}

func (test *ScimGroupTest) clientToken(
	controller *ScimController,
	setup *SesameTestSetup,
	session sesame.IssuedSession,
	canManageGroups bool,
) string {
	return test.registeredClient(controller, setup, session, canManageGroups).Token
}

func (test *ScimGroupTest) createdUser(controller *ScimController, token string, userName string) ScimUser {
	user, err := controller.PostUserCreate(test.bearer(token), ScimResourceCreateRequest{Body: test.userBody(userName)})
	test.check(err)
	return user
}

func (test *ScimGroupTest) userBody(userName string) string {
	return test.encoded(map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": userName,
	})
}

func (test *ScimGroupTest) groupBody(displayName string) string {
	return test.encoded(map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": displayName,
	})
}

func (test *ScimGroupTest) memberPatchBody(principalID string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
		`"Operations":[{"op":"add","path":"members","value":[{"value":"` + principalID + `"}]}]}`
}

func (test *ScimGroupTest) encoded(value any) string {
	encoded, err := json.Marshal(value)
	test.check(err)
	return string(encoded)
}

func (test *ScimGroupTest) check(err error) {
	if err != nil {
		panic(err)
	}
}
