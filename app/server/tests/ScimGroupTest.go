// @Test(SesameTestSetup, {"partition":"tests"})
type ScimGroupTest struct {
	behaviors *BehaviorContext
}

func (test *ScimGroupTest) TestGroupCreateGetAndListFindTheGroup() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller()
	token := setup.ScimClient(controller, session, true).Token

	created, err := controller.PostGroupCreate(setup.Bearer(token), ScimResourceCreateRequest{Body: setup.ScimGroupBody("engineering")})
	group, getErr := controller.PostGroupGet(setup.Bearer(token), ScimResourceRequest{ResourceID: created.ID})
	list, listErr := controller.PostGroupList(setup.Bearer(token), ScimListRequest{})

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
	token := setup.ScimClient(controller, session, true).Token
	user := setup.ScimUserCreated(controller, token, "ada@acme.test")
	created, createErr := controller.PostGroupCreate(setup.Bearer(token), ScimResourceCreateRequest{Body: setup.ScimGroupBody("engineering")})

	group, err := controller.PostGroupPatch(setup.Bearer(token), ScimResourcePatchRequest{
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
	token := setup.ScimClient(controller, session, true).Token
	user := setup.ScimUserCreated(controller, token, "ada@acme.test")
	created, createErr := controller.PostGroupCreate(setup.Bearer(token), ScimResourceCreateRequest{Body: setup.ScimGroupBody("engineering")})
	_, patchErr := controller.PostGroupPatch(setup.Bearer(token), ScimResourcePatchRequest{
		ResourceID: created.ID,
		Body:       test.memberPatchBody(user.ID),
	})

	outcome, err := controller.PostGroupDeprovision(setup.Bearer(token), ScimResourceRequest{ResourceID: created.ID})
	group, getErr := controller.PostGroupGet(setup.Bearer(token), ScimResourceRequest{ResourceID: created.ID})

	Assert.IsTrue(createErr == nil)
	Assert.IsTrue(patchErr == nil)
	Assert.IsTrue(err == nil)
	Assert.IsTrue(outcome.Deprovisioned)
	Assert.IsTrue(getErr == nil)
	Assert.Equals(0, len(group.Members))
}

func (test *ScimGroupTest) controller() *ScimController {
	return SesameTestSetup{}.Scim(SesameTestSetup{}.Engine(), 0)
}

func (test *ScimGroupTest) memberPatchBody(principalID string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
		`"Operations":[{"op":"add","path":"members","value":[{"value":"` + principalID + `"}]}]}`
}
