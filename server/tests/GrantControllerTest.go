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

func (test *GrantControllerTest) TestRevokeRemovesAGrantOfTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	grants, roles, _ := test.controllers()
	request := test.request(setup.Credential(administrator))
	role, _ := roles.PostCreate(request, test.role(administrator.TenantID))
	grant, _ := grants.PostCreate(request, GrantCreateRequest{TenantID: administrator.TenantID, RoleID: role.RoleID, PrincipalID: member.PrincipalID})

	revocation, err := grants.PostRevoke(request, GrantRevokeRequest{GrantID: grant.GrantID})
	_, repeated := grants.PostRevoke(request, GrantRevokeRequest{GrantID: grant.GrantID})

	Assert.IsTrue(err == nil)
	Assert.IsTrue(revocation.Revoked)
	Assert.Equals(http.StatusNotFound, test.status(repeated))
}

func (test *GrantControllerTest) TestRevokeRefusesAGrantOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	member := setup.SignInMember("globex", "member")
	grants, roles, _ := test.controllers()
	owner := test.request(setup.Credential(other))
	role, _ := roles.PostCreate(owner, test.role(other.TenantID))
	grant, _ := grants.PostCreate(owner, GrantCreateRequest{TenantID: other.TenantID, RoleID: role.RoleID, PrincipalID: member.PrincipalID})

	refused, err := grants.PostRevoke(test.request(setup.Credential(administrator)), GrantRevokeRequest{GrantID: grant.GrantID})
	revocation, ownerErr := grants.PostRevoke(owner, GrantRevokeRequest{GrantID: grant.GrantID})

	Assert.Equals(http.StatusForbidden, test.status(err))
	Assert.Equals("actor_tenant_mismatch", test.code(err))
	Assert.IsTrue(!refused.Revoked)
	Assert.IsTrue(ownerErr == nil)
	Assert.IsTrue(revocation.Revoked)
}

func (test *GrantControllerTest) TestRevokeAnswersNotFoundForAnUnknownGrant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	grants, _, _ := test.controllers()

	_, err := grants.PostRevoke(test.request(setup.Credential(administrator)), GrantRevokeRequest{GrantID: "grt_00000000000000000000000000000000"})

	Assert.Equals("grant_not_found", test.code(err))
}

func (test *GrantControllerTest) TestRevokeRefusesAMalformedGrant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	grants, _, _ := test.controllers()

	_, err := grants.PostRevoke(test.request(setup.Credential(administrator)), GrantRevokeRequest{GrantID: "not-a-grant"})

	Assert.Equals(http.StatusBadRequest, test.status(err))
}

func (test *GrantControllerTest) TestRevokeRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	grants, _, _ := test.controllers()

	revocation, err := grants.PostRevoke(httptest.NewRequest(http.MethodPost, "/", nil), GrantRevokeRequest{GrantID: "grt_00000000000000000000000000000000"})

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
	Assert.IsTrue(!revocation.Revoked)
}

func (test *GrantControllerTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
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
	grants := &GrantController{tenantCallService: calls, callerService: callers, engineService: engine}
	return grants, &RoleController{tenantCallService: calls}, groups
}
