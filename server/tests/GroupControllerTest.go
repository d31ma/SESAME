import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type GroupControllerTest struct {
	behaviors *BehaviorContext
}

func (test *GroupControllerTest) TestCreateDefinesAGroupInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	group, err := test.controller().PostCreate(test.request(setup.Credential(administrator)), test.creation(administrator.TenantID))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(group.GroupID != "")
	Assert.Equals(administrator.TenantID, group.TenantID)
	Assert.Equals("editors", group.Name)
}

func (test *GroupControllerTest) TestCreateRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)

	group, err := test.controller().PostCreate(test.request(setup.Credential(administrator)), test.creation(other.TenantID))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", group.GroupID)
}

func (test *GroupControllerTest) TestCreateRefusesATakenName() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	controller := test.controller()
	request := test.request(setup.Credential(administrator))
	_, first := controller.PostCreate(request, test.creation(administrator.TenantID))

	_, err := controller.PostCreate(request, test.creation(administrator.TenantID))

	Assert.IsTrue(first == nil)
	Assert.Equals("group_exists", test.code(err))
}

func (test *GroupControllerTest) TestMemberAddAndRemoveChangeMembership() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	controller := test.controller()
	request := test.request(setup.Credential(administrator))
	group, _ := controller.PostCreate(request, test.creation(administrator.TenantID))
	membership := GroupMemberRequest{GroupID: group.GroupID, PrincipalID: member.PrincipalID}

	added, addFailure := controller.PostMemberAdd(request, membership)
	removed, removeFailure := controller.PostMemberRemove(request, membership)
	_, repeated := controller.PostMemberRemove(request, membership)

	Assert.IsTrue(addFailure == nil)
	Assert.IsTrue(added.Member)
	Assert.IsTrue(removeFailure == nil)
	Assert.IsTrue(!removed.Member)
	Assert.Equals("group_member_not_found", test.code(repeated))
}

func (test *GroupControllerTest) TestMemberAddRefusesARepeatedMember() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	controller := test.controller()
	request := test.request(setup.Credential(administrator))
	group, _ := controller.PostCreate(request, test.creation(administrator.TenantID))
	membership := GroupMemberRequest{GroupID: group.GroupID, PrincipalID: member.PrincipalID}
	_, first := controller.PostMemberAdd(request, membership)

	_, err := controller.PostMemberAdd(request, membership)

	Assert.IsTrue(first == nil)
	Assert.Equals("group_member_exists", test.code(err))
}

func (test *GroupControllerTest) TestMemberAddRefusesAPrincipalOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	request := test.request(setup.Credential(administrator))
	group, _ := controller.PostCreate(request, test.creation(administrator.TenantID))

	membership, err := controller.PostMemberAdd(request, GroupMemberRequest{GroupID: group.GroupID, PrincipalID: other.PrincipalID})

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.IsTrue(!membership.Member)
}

func (test *GroupControllerTest) TestMemberAddRefusesAGroupOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	member := setup.SignInMember("acme", "member")
	controller := test.controller()
	foreign, _ := controller.PostCreate(test.request(setup.Credential(other)), test.creation(other.TenantID))

	membership, err := controller.PostMemberAdd(test.request(setup.Credential(administrator)), GroupMemberRequest{GroupID: foreign.GroupID, PrincipalID: member.PrincipalID})

	Assert.Equals("actor_tenant_mismatch", test.code(err))
	Assert.IsTrue(!membership.Member)
}

func (test *GroupControllerTest) TestMemberRemoveRefusesAPrincipalOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	foreign, _ := controller.PostCreate(test.request(setup.Credential(other)), test.creation(other.TenantID))
	membership := GroupMemberRequest{GroupID: foreign.GroupID, PrincipalID: other.PrincipalID}
	_, joined := controller.PostMemberAdd(test.request(setup.Credential(other)), membership)

	_, err := controller.PostMemberRemove(test.request(setup.Credential(administrator)), membership)
	_, stillMember := controller.PostMemberAdd(test.request(setup.Credential(other)), membership)

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(joined == nil)
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("group_member_exists", test.code(stillMember))
}

func (test *GroupControllerTest) TestMemberAddRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	_, err := test.controller().PostMemberAdd(httptest.NewRequest(http.MethodPost, "/", nil), GroupMemberRequest{PrincipalID: administrator.PrincipalID})

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
}

func (test *GroupControllerTest) creation(tenantID string) GroupCreateRequest {
	return GroupCreateRequest{TenantID: tenantID, Name: "editors"}
}

func (test *GroupControllerTest) code(err error) string {
	protocolError := &sesame.ProtocolError{}
	errors.As(err, &protocolError)
	return protocolError.Code
}

func (test *GroupControllerTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *GroupControllerTest) controller() *GroupController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	callers := &CallerService{engineService: engine}
	return &GroupController{
		tenantCallService:      &TenantCallService{callerService: callers, engineService: engine},
		principalTenantService: &PrincipalTenantService{callerService: callers, engineService: engine},
	}
}
