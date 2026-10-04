import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type RoleControllerTest struct {
	behaviors *BehaviorContext
}

func (test *RoleControllerTest) TestCreateDefinesARoleInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	role, err := test.controller().PostCreate(setup.SignedIn(administrator), test.creation(administrator.TenantID, "doc:read"))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(role.RoleID != "")
	Assert.Equals(administrator.TenantID, role.TenantID)
	Assert.Equals("reader", role.Name)
	Assert.Equals(1, len(role.Permissions))
	Assert.Equals("mfa", role.Permissions[0].Conditions["session.assurance"])
}

func (test *RoleControllerTest) TestCreateRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)

	role, err := test.controller().PostCreate(setup.SignedIn(administrator), test.creation(other.TenantID, "doc:read"))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", role.RoleID)
}

func (test *RoleControllerTest) TestCreateRefusesATakenName() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	controller := test.controller()
	request := setup.SignedIn(administrator)
	_, first := controller.PostCreate(request, test.creation(administrator.TenantID, "doc:read"))

	_, err := controller.PostCreate(request, test.creation(administrator.TenantID, "doc:read"))

	Assert.IsTrue(first == nil)
	Assert.Equals("role_exists", setup.ProtocolCode(err))
}

func (test *RoleControllerTest) TestCreateRefusesAMalformedPermission() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	_, err := test.controller().PostCreate(setup.SignedIn(administrator), test.creation(administrator.TenantID, "Read Everything"))

	Assert.Equals("invalid_request", setup.ProtocolCode(err))
}

func (test *RoleControllerTest) TestCreateRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	_, err := test.controller().PostCreate(httptest.NewRequest(http.MethodPost, "/", nil), test.creation(administrator.TenantID, "doc:read"))

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
}

func (test *RoleControllerTest) creation(tenantID string, action string) RoleCreateRequest {
	return RoleCreateRequest{
		TenantID: tenantID,
		Name:     "reader",
		Permissions: []RolePermission{{
			Action:     action,
			Resource:   "file:*",
			Conditions: map[string]string{"session.assurance": "mfa"},
		}},
	}
}

func (test *RoleControllerTest) controller() *RoleController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &RoleController{tenantCallService: SesameTestSetup{}.TenantCalls(engine)}
}
