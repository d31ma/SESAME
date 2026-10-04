import (
	"errors"
	"net/http"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type PrincipalControllerTest struct {
	behaviors *BehaviorContext
}

func (test *PrincipalControllerTest) TestCreateRegistersAPrincipalInTheCallersTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	principal, err := test.controller().PostCreate(setup.SignedIn(administrator), test.creation(administrator.TenantID))

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

	principal, err := test.controller().PostCreate(setup.SignedIn(administrator), test.creation(other.TenantID))

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", principal.PrincipalID)
}

func (test *PrincipalControllerTest) TestCreateRefusesAClaimedIdentifier() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	controller := test.controller()
	request := setup.SignedIn(administrator)
	_, first := controller.PostCreate(request, test.creation(administrator.TenantID))

	_, err := controller.PostCreate(request, test.creation(administrator.TenantID))

	Assert.IsTrue(first == nil)
	Assert.Equals("identifier_conflict", setup.ProtocolCode(err))
}

func (test *PrincipalControllerTest) TestCreateRefusesAMemberEvenWithoutTheRouteGuard() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	controller := test.controller()

	principal, err := controller.PostCreate(setup.SignedIn(member), test.creation(member.TenantID))
	_, lookup := controller.PostGet(setup.SignedIn(administrator), test.lookupService(administrator.TenantID, "builder"))

	Assert.Equals(http.StatusForbidden, (&SesameErrorHandler{}).Answer(err).StatusCode)
	Assert.Equals("administrator_required", test.publicCode(err))
	Assert.Equals("", principal.PrincipalID)
	Assert.Equals("principal_not_found", test.publicCode(lookup))
}

func (test *PrincipalControllerTest) TestCreateRejectsAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	_, err := test.controller().PostCreate(setup.Anonymous(), test.creation(administrator.TenantID))

	var rejected *host.SessionRejectedError
	Assert.IsTrue(errors.As(err, &rejected))
}

func (test *PrincipalControllerTest) TestGetFindsAPrincipalByID() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")

	principal, err := test.controller().PostGet(setup.SignedIn(administrator), PrincipalGetRequest{PrincipalID: member.PrincipalID})

	Assert.IsTrue(err == nil)
	Assert.Equals(member.PrincipalID, principal.PrincipalID)
	Assert.Equals("member@acme.test", principal.Identifier.Value)
}

func (test *PrincipalControllerTest) TestGetFindsAPrincipalByIdentifier() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")

	principal, err := test.controller().PostGet(setup.SignedIn(administrator), test.lookup(administrator.TenantID, "member@acme.test"))

	Assert.IsTrue(err == nil)
	Assert.Equals(member.PrincipalID, principal.PrincipalID)
}

func (test *PrincipalControllerTest) TestGetRefusesAPrincipalOfAnotherTenantByID() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)

	principal, err := test.controller().PostGet(setup.SignedIn(administrator), PrincipalGetRequest{PrincipalID: other.PrincipalID})

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(err, &mismatch))
	Assert.Equals("", principal.Identifier.Value)
}

func (test *PrincipalControllerTest) TestGetRefusesAnIdentifierOfAnotherTenant() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)

	principal, err := test.controller().PostGet(setup.SignedIn(administrator), test.lookup(other.TenantID, "person@globex.test"))

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

	principal, err := test.controller().PostGet(setup.SignedIn(administrator), lookup)

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

	principal, err := test.controller().PostGet(setup.SignedIn(administrator), lookup)

	var mixed *host.MixedPrincipalLookupError
	Assert.IsTrue(errors.As(err, &mixed))
	Assert.Equals("", principal.PrincipalID)
}

func (test *PrincipalControllerTest) TestGetRefusesAnEmptyRequest() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)

	_, err := test.controller().PostGet(setup.SignedIn(administrator), PrincipalGetRequest{})

	Assert.Equals("invalid_request", setup.ProtocolCode(err))
}

func (test *PrincipalControllerTest) TestSuspendSuspendsAPrincipalOfTheCallersTenantAndRepeats() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	controller := test.controller()
	request := setup.SignedIn(administrator)
	_, first := controller.PostSuspend(request, PrincipalReference{PrincipalID: member.PrincipalID})

	principal, err := controller.PostSuspend(request, PrincipalReference{PrincipalID: member.PrincipalID})

	Assert.IsTrue(first == nil)
	Assert.IsTrue(err == nil)
	Assert.Equals("suspended", principal.Status)
}

func (test *PrincipalControllerTest) TestSuspendNeedsARecentSignIn() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := setup.Engine()
	request := setup.SignedIn(administrator)

	_, err := test.controllerWith(engine, 11*time.Minute).PostSuspend(request, PrincipalReference{PrincipalID: member.PrincipalID})
	untouched, check := test.controllerWith(engine, 0).PostGet(request, PrincipalGetRequest{PrincipalID: member.PrincipalID})

	Assert.IsTrue(setup.ReauthenticationRequired(err))
	Assert.IsTrue(check == nil)
	Assert.Equals("active", untouched.Status)
}

func (test *PrincipalControllerTest) TestSuspendRefusesAPrincipalOfAnotherTenantAndLeavesItActive() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignIn("globex", true)
	controller := test.controller()

	_, err := controller.PostSuspend(setup.SignedIn(administrator), PrincipalReference{PrincipalID: other.PrincipalID})
	untouched, check := controller.PostGet(setup.SignedIn(other), PrincipalGetRequest{PrincipalID: other.PrincipalID})

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

func (test *PrincipalControllerTest) lookupService(tenantID string, value string) PrincipalGetRequest {
	return PrincipalGetRequest{TenantID: tenantID, IdentifierNamespace: "service", IdentifierValue: value}
}

func (test *PrincipalControllerTest) publicCode(err error) string {
	var coded host.CodedError
	errors.As(err, &coded)
	if coded == nil {
		return ""
	}
	return coded.ErrorCode()
}

func (test *PrincipalControllerTest) controller() *PrincipalController {
	return test.controllerWith(SesameTestSetup{}.Engine(), 0)
}

func (test *PrincipalControllerTest) controllerWith(engine *EngineService, elapsed time.Duration) *PrincipalController {
	return SesameTestSetup{}.Principals(engine, elapsed)
}
