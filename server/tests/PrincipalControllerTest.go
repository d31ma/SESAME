import (
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/host"
	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type PrincipalControllerTest struct {
	behaviors *BehaviorContext
}

func (test *PrincipalControllerTest) TestCreateRegistersAPrincipalInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	principal, err := test.controller().PostCreate(test.request(setup.Credential(administrator)), test.creation(administrator.TenantID))

	Assert.IsTrue(err == nil)
	Assert.Equals(administrator.TenantID, principal.TenantID)
	Assert.Equals("workload", principal.Kind)
	Assert.Equals("active", principal.Status)
	Assert.Equals("builder", principal.Identifier.Value)
}

func (test *PrincipalControllerTest) TestCreateRefusesAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)

	principal, err := test.controller().PostCreate(test.request(setup.Credential(administrator)), test.creation(other.TenantID))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", principal.PrincipalID)
}

func (test *PrincipalControllerTest) TestCreateRefusesAClaimedIdentifier() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	controller := test.controller()
	request := test.request(setup.Credential(administrator))
	_, first := controller.PostCreate(request, test.creation(administrator.TenantID))

	_, err := controller.PostCreate(request, test.creation(administrator.TenantID))

	Assert.IsTrue(first == nil)
	Assert.Equals("identifier_conflict", test.code(err))
}

func (test *PrincipalControllerTest) TestCreateRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	_, err := test.controller().PostCreate(test.anonymous(), test.creation(administrator.TenantID))

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
}

func (test *PrincipalControllerTest) TestGetFindsAPrincipalByID() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")

	principal, err := test.controller().PostGet(test.request(setup.Credential(administrator)), PrincipalGetRequest{PrincipalID: member.PrincipalID})

	Assert.IsTrue(err == nil)
	Assert.Equals(member.PrincipalID, principal.PrincipalID)
	Assert.Equals("member@acme.test", principal.Identifier.Value)
}

func (test *PrincipalControllerTest) TestGetFindsAPrincipalByIdentifier() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")

	principal, err := test.controller().PostGet(test.request(setup.Credential(administrator)), test.lookup(administrator.TenantID, "member@acme.test"))

	Assert.IsTrue(err == nil)
	Assert.Equals(member.PrincipalID, principal.PrincipalID)
}

func (test *PrincipalControllerTest) TestGetRefusesAPrincipalOfAnotherTenantByID() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)

	principal, err := test.controller().PostGet(test.request(setup.Credential(administrator)), PrincipalGetRequest{PrincipalID: other.PrincipalID})

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", principal.Identifier.Value)
}

func (test *PrincipalControllerTest) TestGetRefusesAnIdentifierOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)

	principal, err := test.controller().PostGet(test.request(setup.Credential(administrator)), test.lookup(other.TenantID, "person@globex.test"))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", principal.PrincipalID)
}

func (test *PrincipalControllerTest) TestGetRefusesAForeignPrincipalIDNamedWithTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	lookup := PrincipalGetRequest{TenantID: administrator.TenantID, PrincipalID: other.PrincipalID}

	principal, err := test.controller().PostGet(test.request(setup.Credential(administrator)), lookup)

	var mixed *host.MixedPrincipalLookupError
	Assert.IsTrue(errors.As(err, &mixed))
	Assert.Equals("invalid_request", test.publicCode(err))
	Assert.Equals("", principal.PrincipalID)
	Assert.Equals("", principal.Identifier.Value)
}

func (test *PrincipalControllerTest) TestGetRefusesAPrincipalIDMixedWithAnIdentifier() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	lookup := PrincipalGetRequest{PrincipalID: administrator.PrincipalID, IdentifierNamespace: "email", IdentifierValue: "person@acme.test"}

	principal, err := test.controller().PostGet(test.request(setup.Credential(administrator)), lookup)

	var mixed *host.MixedPrincipalLookupError
	Assert.IsTrue(errors.As(err, &mixed))
	Assert.Equals("", principal.PrincipalID)
}

func (test *PrincipalControllerTest) TestGetRefusesAnEmptyRequest() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	_, err := test.controller().PostGet(test.request(setup.Credential(administrator)), PrincipalGetRequest{})

	Assert.Equals("invalid_request", test.code(err))
}

func (test *PrincipalControllerTest) TestSuspendSuspendsAPrincipalOfTheCallersTenantAndRepeats() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	controller := test.controller()
	request := test.request(setup.Credential(administrator))
	_, first := controller.PostSuspend(request, PrincipalReference{PrincipalID: member.PrincipalID})

	principal, err := controller.PostSuspend(request, PrincipalReference{PrincipalID: member.PrincipalID})

	Assert.IsTrue(first == nil)
	Assert.IsTrue(err == nil)
	Assert.Equals("suspended", principal.Status)
}

func (test *PrincipalControllerTest) TestSuspendRefusesAPrincipalOfAnotherTenantAndLeavesItActive() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()

	_, err := controller.PostSuspend(test.request(setup.Credential(administrator)), PrincipalReference{PrincipalID: other.PrincipalID})
	untouched, check := controller.PostGet(test.request(setup.Credential(other)), PrincipalGetRequest{PrincipalID: other.PrincipalID})

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.IsTrue(check == nil)
	Assert.Equals("active", untouched.Status)
}

func (test *PrincipalControllerTest) creation(tenantID string) PrincipalCreateRequest {
	return PrincipalCreateRequest{
		TenantID:            tenantID,
		Kind:                "workload",
		IdentifierNamespace: "service",
		IdentifierValue:     "builder",
	}
}

func (test *PrincipalControllerTest) lookup(tenantID string, value string) PrincipalGetRequest {
	return PrincipalGetRequest{TenantID: tenantID, IdentifierNamespace: "email", IdentifierValue: value}
}

func (test *PrincipalControllerTest) code(err error) string {
	protocolError := &sesame.ProtocolError{}
	errors.As(err, &protocolError)
	return protocolError.Code
}

func (test *PrincipalControllerTest) publicCode(err error) string {
	var coded host.CodedError
	errors.As(err, &coded)
	if coded == nil {
		return ""
	}
	return coded.ErrorCode()
}

func (test *PrincipalControllerTest) anonymous() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}

func (test *PrincipalControllerTest) request(credential string) *http.Request {
	request := test.anonymous()
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *PrincipalControllerTest) controller() *PrincipalController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	callers := &CallerService{engineService: engine}
	return &PrincipalController{
		tenantCallService:      &TenantCallService{callerService: callers, engineService: engine},
		principalTenantService: &PrincipalTenantService{callerService: callers, engineService: engine},
	}
}
