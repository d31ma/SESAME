import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type GrantControllerTest struct {
	behaviors *BehaviorContext
}

func (test *GrantControllerTest) TestCreateGrantsARoleToAPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	grants, roles, _ := test.controllers()
	request := test.request(setup.Credential(administrator))
	role, _ := roles.PostCreate(request, test.role(administrator.TenantID))

	grant, err := grants.PostCreate(request, GrantCreateRequest{TenantID: administrator.TenantID, RoleID: role.RoleID, PrincipalID: member.PrincipalID})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(grant.GrantID != "")
	Assert.Equals(administrator.TenantID, grant.TenantID)
	Assert.Equals(member.PrincipalID, grant.PrincipalID)
	Assert.Equals(role.RoleID, grant.RoleID)
}

func (test *GrantControllerTest) TestCreateGrantsARoleToAGroup() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	grants, roles, groups := test.controllers()
	request := test.request(setup.Credential(administrator))
	role, _ := roles.PostCreate(request, test.role(administrator.TenantID))
	group, _ := groups.PostCreate(request, GroupCreateRequest{TenantID: administrator.TenantID, Name: "readers"})

	grant, err := grants.PostCreate(request, GrantCreateRequest{TenantID: administrator.TenantID, RoleID: role.RoleID, GroupID: group.GroupID})

	Assert.IsTrue(err == nil)
	Assert.Equals(group.GroupID, grant.GroupID)
	Assert.Equals("", grant.PrincipalID)
}

func (test *GrantControllerTest) TestCreateRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	grants, roles, _ := test.controllers()
	role, _ := roles.PostCreate(test.request(setup.Credential(other)), test.role(other.TenantID))

	grant, err := grants.PostCreate(test.request(setup.Credential(administrator)), GrantCreateRequest{TenantID: other.TenantID, RoleID: role.RoleID, PrincipalID: other.PrincipalID})

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", grant.GrantID)
}

func (test *GrantControllerTest) TestCreateRefusesARoleOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	member := setup.SignInMember("acme", "member")
	grants, roles, _ := test.controllers()
	foreign, _ := roles.PostCreate(test.request(setup.Credential(other)), test.role(other.TenantID))

	grant, err := grants.PostCreate(test.request(setup.Credential(administrator)), GrantCreateRequest{TenantID: administrator.TenantID, RoleID: foreign.RoleID, PrincipalID: member.PrincipalID})

	Assert.Equals("role_not_found", test.code(err))
	Assert.Equals("", grant.GrantID)
}

func (test *GrantControllerTest) TestCreateRefusesAPrincipalOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	grants, roles, _ := test.controllers()
	request := test.request(setup.Credential(administrator))
	role, _ := roles.PostCreate(request, test.role(administrator.TenantID))

	_, err := grants.PostCreate(request, GrantCreateRequest{TenantID: administrator.TenantID, RoleID: role.RoleID, PrincipalID: other.PrincipalID})

	Assert.Equals("principal_not_found", test.code(err))
}

func (test *GrantControllerTest) TestCreateRefusesTwoSubjects() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	grants, roles, groups := test.controllers()
	request := test.request(setup.Credential(administrator))
	role, _ := roles.PostCreate(request, test.role(administrator.TenantID))
	group, _ := groups.PostCreate(request, GroupCreateRequest{TenantID: administrator.TenantID, Name: "readers"})

	_, err := grants.PostCreate(request, GrantCreateRequest{TenantID: administrator.TenantID, RoleID: role.RoleID, PrincipalID: member.PrincipalID, GroupID: group.GroupID})

	Assert.Equals("invalid_request", test.code(err))
}

func (test *GrantControllerTest) TestCreateRefusesARepeatedGrant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	grants, roles, _ := test.controllers()
	request := test.request(setup.Credential(administrator))
	role, _ := roles.PostCreate(request, test.role(administrator.TenantID))
	creation := GrantCreateRequest{TenantID: administrator.TenantID, RoleID: role.RoleID, PrincipalID: member.PrincipalID}
	_, first := grants.PostCreate(request, creation)

	_, err := grants.PostCreate(request, creation)

	Assert.IsTrue(first == nil)
	Assert.Equals("grant_exists", test.code(err))
}

func (test *GrantControllerTest) TestCreateRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	grants, _, _ := test.controllers()

	_, err := grants.PostCreate(httptest.NewRequest(http.MethodPost, "/", nil), GrantCreateRequest{TenantID: administrator.TenantID})

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
}

func (test *GrantControllerTest) role(tenantID string) RoleCreateRequest {
	return RoleCreateRequest{
		TenantID:    tenantID,
		Name:        "reader",
		Permissions: []RolePermission{{Action: "doc:read", Resource: "file:*"}},
	}
}

func (test *GrantControllerTest) code(err error) string {
	protocolError := &sesame.ProtocolError{}
	errors.As(err, &protocolError)
	return protocolError.Code
}

func (test *GrantControllerTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *GrantControllerTest) controllers() (*GrantController, *RoleController, *GroupController) {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	callers := &CallerService{engineService: engine}
	calls := &TenantCallService{callerService: callers, engineService: engine}
	principals := &PrincipalTenantService{callerService: callers, engineService: engine}
	groups := &GroupController{tenantCallService: calls, principalTenantService: principals}
	return &GrantController{tenantCallService: calls}, &RoleController{tenantCallService: calls}, groups
}
