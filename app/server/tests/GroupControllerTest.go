import (
	"errors"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type GroupControllerTest struct {
	behaviors *BehaviorContext
}

func (test *GroupControllerTest) TestCreateDefinesAGroupInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	group, err := test.controller().PostCreate(setup.SignedIn(administrator), test.creation(administrator.TenantID))

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

	group, err := test.controller().PostCreate(setup.SignedIn(administrator), test.creation(other.TenantID))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", group.GroupID)
}

func (test *GroupControllerTest) TestCreateRefusesATakenName() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	controller := test.controller()
	request := setup.SignedIn(administrator)
	_, first := controller.PostCreate(request, test.creation(administrator.TenantID))

	_, err := controller.PostCreate(request, test.creation(administrator.TenantID))

	Assert.IsTrue(first == nil)
	Assert.Equals("group_exists", setup.ProtocolCode(err))
}

func (test *GroupControllerTest) TestMemberAddAndRemoveChangeMembership() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	controller := test.controller()
	request := setup.SignedIn(administrator)
	group, _ := controller.PostCreate(request, test.creation(administrator.TenantID))
	membership := GroupMemberRequest{GroupID: group.GroupID, PrincipalID: member.PrincipalID}

	added, addFailure := controller.PostMemberAdd(request, membership)
	removed, removeFailure := controller.PostMemberRemove(request, membership)
	_, repeated := controller.PostMemberRemove(request, membership)

	Assert.IsTrue(addFailure == nil)
	Assert.IsTrue(added.Member)
	Assert.IsTrue(removeFailure == nil)
	Assert.IsTrue(!removed.Member)
	Assert.Equals("group_member_not_found", setup.ProtocolCode(repeated))
}

func (test *GroupControllerTest) TestMemberAddNeedsARecentSignInAndMemberRemoveDoesNot() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	other := setup.SignInMember("acme", "other")
	engine := setup.Engine()
	fresh := test.controllerWith(engine, 0)
	stale := test.controllerWith(engine, 11*time.Minute)
	request := setup.SignedIn(administrator)
	group, _ := fresh.PostCreate(request, test.creation(administrator.TenantID))
	_, _ = fresh.PostMemberAdd(request, GroupMemberRequest{GroupID: group.GroupID, PrincipalID: other.PrincipalID})

	added, err := stale.PostMemberAdd(request, GroupMemberRequest{GroupID: group.GroupID, PrincipalID: member.PrincipalID})
	removed, removeErr := stale.PostMemberRemove(request, GroupMemberRequest{GroupID: group.GroupID, PrincipalID: other.PrincipalID})
	_, notMember := fresh.PostMemberRemove(request, GroupMemberRequest{GroupID: group.GroupID, PrincipalID: member.PrincipalID})

	Assert.IsTrue(setup.ReauthenticationRequired(err))
	Assert.IsTrue(!added.Member)
	Assert.IsTrue(removeErr == nil)
	Assert.IsTrue(!removed.Member)
	Assert.Equals("group_member_not_found", setup.ProtocolCode(notMember))
}

func (test *GroupControllerTest) TestMemberAddRefusesARepeatedMember() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	controller := test.controller()
	request := setup.SignedIn(administrator)
	group, _ := controller.PostCreate(request, test.creation(administrator.TenantID))
	membership := GroupMemberRequest{GroupID: group.GroupID, PrincipalID: member.PrincipalID}
	_, first := controller.PostMemberAdd(request, membership)

	_, err := controller.PostMemberAdd(request, membership)

	Assert.IsTrue(first == nil)
	Assert.Equals("group_member_exists", setup.ProtocolCode(err))
}

func (test *GroupControllerTest) TestMemberAddRefusesAPrincipalOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	request := setup.SignedIn(administrator)
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
	foreign, _ := controller.PostCreate(setup.SignedIn(other), test.creation(other.TenantID))

	membership, err := controller.PostMemberAdd(setup.SignedIn(administrator), GroupMemberRequest{GroupID: foreign.GroupID, PrincipalID: member.PrincipalID})

	Assert.Equals("actor_tenant_mismatch", setup.ProtocolCode(err))
	Assert.IsTrue(!membership.Member)
}

func (test *GroupControllerTest) TestMemberRemoveRefusesAPrincipalOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()
	foreign, _ := controller.PostCreate(setup.SignedIn(other), test.creation(other.TenantID))
	membership := GroupMemberRequest{GroupID: foreign.GroupID, PrincipalID: other.PrincipalID}
	_, joined := controller.PostMemberAdd(setup.SignedIn(other), membership)

	_, err := controller.PostMemberRemove(setup.SignedIn(administrator), membership)
	_, stillMember := controller.PostMemberAdd(setup.SignedIn(other), membership)

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(joined == nil)
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("group_member_exists", setup.ProtocolCode(stillMember))
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

func (test *GroupControllerTest) controller() *GroupController {
	return test.controllerWith(SesameTestSetup{}.Engine(), 0)
}

func (test *GroupControllerTest) controllerWith(engine *EngineService, elapsed time.Duration) *GroupController {
	calls := SesameTestSetup{}.TenantCallsAfter(engine, elapsed)
	return &GroupController{
		tenantCallService:      calls,
		principalTenantService: &PrincipalTenantService{tenantCallService: calls},
	}
}
