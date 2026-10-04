import (
	"strings"
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
	token := setup.ScimClient(controller, session, false).Token

	user, err := controller.PostUserCreate(setup.Bearer(token), ScimResourceCreateRequest{Body: setup.ScimUserBody("ada@acme.test")})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(user.ID != "")
	Assert.Equals("ada@acme.test", user.UserName)
	Assert.IsTrue(user.Active)
	Assert.IsTrue(!strings.Contains(setup.Encoded(user), token))
}

func (test *ScimUserTest) TestUserGetAndListFindTheUser() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := setup.ScimClient(controller, session, false).Token
	created := setup.ScimUserCreated(controller, token, "ada@acme.test")

	user, err := controller.PostUserGet(setup.Bearer(token), ScimResourceRequest{ResourceID: created.ID})
	list, listErr := controller.PostUserList(setup.Bearer(token), ScimListRequest{Filter: `userName eq "ada@acme.test"`})

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
	token := setup.ScimClient(controller, session, false).Token
	created := setup.ScimUserCreated(controller, token, "ada@acme.test")

	user, err := controller.PostUserPatch(setup.Bearer(token), ScimResourcePatchRequest{
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
	token := setup.ScimClient(controller, session, false).Token
	created := setup.ScimUserCreated(controller, token, "ada@acme.test")

	outcome, err := controller.PostUserDeprovision(setup.Bearer(token), ScimResourceRequest{ResourceID: created.ID})
	user, getErr := controller.PostUserGet(setup.Bearer(token), ScimResourceRequest{ResourceID: created.ID})

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

func (test *ScimUserTest) patchBody(path string, value string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
		`"Operations":[{"op":"replace","path":"` + path + `","value":` + value + `}]}`
}
