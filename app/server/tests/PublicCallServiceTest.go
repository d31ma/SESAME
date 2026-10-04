import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type PublicCallServiceTest struct {
	behaviors *BehaviorContext
}

func (test *PublicCallServiceTest) TestCallRefusesANonPublicOperationAndNothingIsWritten() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := setup.Engine()
	defer setup.Finish(engine)
	request := setup.SignedIn(administrator)
	role, _ := (&RoleController{tenantCallService: setup.TenantCalls(engine)}).PostCreate(request, test.role(administrator.TenantID))
	create := GrantCreateRequest{TenantID: administrator.TenantID, RoleID: role.RoleID, PrincipalID: member.PrincipalID}
	refused := Grant{}

	err := setup.PublicCalls(engine).Call(EngineCall{Operation: "grant.create", Parameters: create, Result: &refused})
	grant, grantErr := (&GrantController{tenantCallService: setup.TenantCalls(engine)}).PostCreate(request, create)

	Assert.IsTrue(test.notPublic(err))
	Assert.Equals(http.StatusInternalServerError, setup.Status(err))
	Assert.Equals("internal_error", test.answeredCode(err))
	Assert.Equals("", refused.GrantID)
	Assert.IsTrue(grantErr == nil)
	Assert.IsTrue(grant.GrantID != "")
}

func (test *PublicCallServiceTest) TestCallRefusesANonPublicOperationBeforeTheEngineIsReached() {
	err := SesameTestSetup{}.PublicCalls(SesameTestSetup{}.Engine()).Call(EngineCall{
		Operation:  "principal.suspend",
		Parameters: struct{}{},
		Result:     &struct{}{},
	})

	Assert.IsTrue(test.notPublic(err))
}

func (test *PublicCallServiceTest) TestEveryRoutedPublicOperationStillReachesTheEngine() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	engine := setup.Engine()
	defer setup.Finish(engine)
	ping, pingErr := setup.System(engine).PostPing()

	failures := test.publicRouteFailures(engine)

	Assert.IsTrue(pingErr == nil)
	Assert.Equals("ok", ping.Status)
	Assert.Equals(0, test.notPublicCount(failures))
}

func (test *PublicCallServiceTest) publicRouteFailures(engine *EngineHelper) []error {
	failures := test.authnFailures(engine)
	failures = append(failures, test.federatedLoginFailures(engine)...)
	failures = append(failures, test.oidcFailures(engine)...)
	return append(failures, test.engineFailures(engine)...)
}

func (test *PublicCallServiceTest) authnFailures(engine *EngineHelper) []error {
	authn := SesameTestSetup{}.Authn(engine)
	_, begin := authn.PostBegin(AuthnBeginRequest{})
	_, password := authn.PostVerifyPassword(AuthnVerifyPasswordRequest{})
	_, totp := authn.PostVerifyTotp(AuthnCodeRequest{})
	_, recoveryCode := authn.PostVerifyRecoveryCode(AuthnCodeRequest{})
	_, passkeyOptions := authn.PostPasskeyOptions(AuthnTransactionRequest{})
	_, passkey := authn.PostVerifyPasskey(AuthnVerifyPasskeyRequest{})
	_, complete := authn.PostComplete(AuthnCompleteRequest{})
	return []error{begin, password, totp, recoveryCode, passkeyOptions, passkey, complete}
}

func (test *PublicCallServiceTest) federatedLoginFailures(engine *EngineHelper) []error {
	_, federation := SesameTestSetup{}.Federation(engine, 0).PostLoginComplete(FederationLoginCompleteRequest{})
	_, saml := SesameTestSetup{}.Saml(engine, 0).PostLoginComplete(SamlLoginCompleteRequest{})
	return []error{federation, saml}
}

func (test *PublicCallServiceTest) oidcFailures(engine *EngineHelper) []error {
	oidc := SesameTestSetup{}.Oidc(engine)
	_, pushed := oidc.PostPushedAuthorize(OidcPushedAuthorizeRequest{})
	_, device := oidc.PostDeviceAuthorize(OidcDeviceAuthorizeRequest{})
	_, dpop := oidc.PostDpopVerify(OidcDpopVerifyRequest{})
	return []error{pushed, device, dpop}
}

func (test *PublicCallServiceTest) engineFailures(engine *EngineHelper) []error {
	system := SesameTestSetup{}.System(engine)
	_, version := system.PostVersion()
	_, readiness := system.PostReadiness()
	_, keys := SesameTestSetup{}.Token(engine).PostJwks()
	_, session := SesameTestSetup{}.Sessions(engine, 0).PostVerify(SessionCredential{})
	return []error{version, readiness, keys, session}
}

func (test *PublicCallServiceTest) notPublicCount(failures []error) int {
	count := 0
	for _, failure := range failures {
		if test.notPublic(failure) {
			count++
		}
	}
	return count
}

func (test *PublicCallServiceTest) notPublic(err error) bool {
	var refusal *host.OperationNotPublicError
	return errors.As(err, &refusal)
}

func (test *PublicCallServiceTest) answeredCode(err error) string {
	body, _ := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	problem := Problem{}
	json.Unmarshal(body, &problem)
	return problem.Code
}

func (test *PublicCallServiceTest) role(tenantID string) RoleCreateRequest {
	return RoleCreateRequest{
		TenantID:    tenantID,
		Name:        "reader",
		Permissions: []RolePermission{{Action: "doc:read", Resource: "file:*"}},
	}
}
