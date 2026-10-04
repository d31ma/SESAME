import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/d31ma/sesame/app/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type ActorAttributionTest struct {
	behaviors *BehaviorContext
}

func (test *ActorAttributionTest) TestAdministratorWriteRecordsTheCallingPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := setup.Engine()

	_, err := test.principals(engine).PostSuspend(setup.SignedIn(administrator), PrincipalReference{PrincipalID: member.PrincipalID})
	test.finish(engine)

	Assert.IsTrue(err == nil)
	Assert.Equals(test.principalActor(administrator), test.actors(setup, "principal.suspended"))
}

func (test *ActorAttributionTest) TestSelfServiceWriteRecordsTheCallingPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignInMember("acme", "member")
	engine := setup.Engine()
	sessions := setup.Sessions(engine, 0)

	_, err := sessions.PostRevoke(setup.SignedIn(member), SessionRevokeReason{Reason: "signed_out"})
	test.finish(engine)

	Assert.IsTrue(err == nil)
	Assert.Equals(test.principalActor(member), test.actors(setup, "session.revoked"))
}

func (test *ActorAttributionTest) TestGrantRevokeRecordsTheCallingPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := setup.Engine()
	calls := setup.TenantCalls(engine)
	grants := &GrantController{tenantCallService: calls}
	request := setup.SignedIn(administrator)
	role, _ := (&RoleController{tenantCallService: calls}).PostCreate(request, RoleCreateRequest{
		TenantID: administrator.TenantID, Name: "reader", Permissions: []RolePermission{{Action: "doc:read", Resource: "file:*"}},
	})
	grant, _ := grants.PostCreate(request, GrantCreateRequest{TenantID: administrator.TenantID, RoleID: role.RoleID, PrincipalID: member.PrincipalID})

	_, err := grants.PostRevoke(request, GrantRevokeRequest{GrantID: grant.GrantID})
	test.finish(engine)

	Assert.IsTrue(err == nil)
	Assert.Equals(test.principalActor(administrator), test.actors(setup, "grant.revoked"))
}

func (test *ActorAttributionTest) TestRefusedCrossTenantRevokeRecordsNothing() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	other := setup.SignInMember("globex", "member")
	engine := setup.Engine()
	sessions := setup.Sessions(engine, 0)

	_, err := sessions.PostRevokeByID(setup.SignedIn(administrator), SessionRevokeRequest{SessionID: other.SessionID})
	test.finish(engine)

	Assert.Equals(http.StatusForbidden, (&SesameErrorHandler{}).Answer(err).StatusCode)
	Assert.Equals("", test.actors(setup, "session.revoked"))
}

func (test *ActorAttributionTest) TestTenantRecordCallRecordsTheCallingPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	engine := setup.Engine()
	clients := setup.OidcClients(engine, 0)
	request := setup.SignedIn(administrator)
	registered, _ := clients.PostRegister(request, OidcClientRegisterRequest{
		TenantID: administrator.TenantID, Name: "Portal", ClientType: "confidential",
		Redirects: []string{"https://rp.example/callback"}, Scopes: []string{"openid"}, Audience: "first_party",
	})

	_, err := clients.PostDisable(request, OidcClientDisableRequest{ClientID: registered.Client.ClientID, Reason: "retired"})
	test.finish(engine)

	Assert.IsTrue(err == nil)
	Assert.Equals(test.principalActor(administrator), test.actors(setup, "oidc_client.disabled"))
}

func (test *ActorAttributionTest) TestCallerCallRecordsTheCallingPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignInMember("acme", "member")
	engine := setup.Engine()
	oidc := setup.Oidc(engine)
	registered := sesame.ClientRegistration{}
	registerErr := engine.Call("oidc_client.register", map[string]any{
		"tenant_id": member.TenantID, "name": "Portal", "client_type": "confidential",
		"redirect_uris": []string{"https://rp.example/callback"}, "scopes": []string{"openid"}, "audience": "first_party",
	}, &registered)
	started, _ := oidc.PostDeviceAuthorize(OidcDeviceAuthorizeRequest{ClientID: registered.Client.ID, Scopes: []string{"openid"}})

	_, err := oidc.PostDeviceDeny(setup.SignedIn(member), OidcUserCodeRequest{UserCode: started.UserCode})
	test.finish(engine)

	Assert.IsTrue(registerErr == nil)
	Assert.IsTrue(err == nil)
	Assert.Equals("operator:machine", test.actors(setup, "oidc.device_authorization_started"))
	Assert.Equals(test.principalActor(member), test.actors(setup, "oidc.device_authorization_denied"))
}

func (test *ActorAttributionTest) TestCallActsAsTheBoundCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	engine := setup.Engine()

	engine.ActAs(Caller{TenantID: administrator.TenantID, PrincipalID: administrator.PrincipalID, SessionID: administrator.SessionID})
	err := engine.Call("principal.create", test.creation(administrator.TenantID), &Principal{})
	test.finish(engine)

	Assert.IsTrue(err == nil)
	Assert.Equals("operator:machine,"+test.principalActor(administrator), test.actors(setup, "principal.created"))
}

func (test *ActorAttributionTest) TestCallWithoutACallerRecordsTheMachineOperator() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	engine := setup.Engine()

	err := engine.Call("principal.create", test.creation(administrator.TenantID), &Principal{})
	test.finish(engine)

	Assert.IsTrue(err == nil)
	Assert.Equals("operator:machine,operator:machine", test.actors(setup, "principal.created"))
}

func (test *ActorAttributionTest) TestRejectedCallerBindsNoActor() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	engine := setup.Engine()

	_, rejected := (&CallerService{engineHelper: engine}).Resolve(httptest.NewRequest(http.MethodPost, "/", nil))
	err := engine.Call("principal.create", test.creation(administrator.TenantID), &Principal{})
	test.finish(engine)

	Assert.IsTrue(rejected != nil)
	Assert.IsTrue(err == nil)
	Assert.Equals("operator:machine,operator:machine", test.actors(setup, "principal.created"))
}

func (test *ActorAttributionTest) TestCallRefusesAnActorTheEngineCannotRecord() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	setup.UseSettings(map[string]any{"binary": test.engineWithoutAttribution(setup), "deployment": setup.deployment})
	bound := setup.Engine()
	unbound := setup.Engine()

	bound.ActAs(Caller{TenantID: "tnt_1", PrincipalID: "prn_1", SessionID: "ses_1"})
	boundErr := bound.Call("system.ping", struct{}{}, &SystemPing{})
	unboundErr := unbound.Call("system.ping", struct{}{}, &SystemPing{})

	var incompatible *sesame.IncompatibleEngineError
	Assert.IsTrue(errors.As(boundErr, &incompatible))
	Assert.Equals(http.StatusInternalServerError, (&SesameErrorHandler{}).Answer(boundErr).StatusCode)
	Assert.IsTrue(unboundErr == nil)
}

func (test *ActorAttributionTest) engineWithoutAttribution(setup *SesameTestSetup) string {
	script := filepath.Join(setup.directory, "engine-without-attribution")
	answer := `{"protocol_version":"1","request_id":"%s","ok":true,` +
		`"result":{"name":"sesame","version":"old","protocol_version":"1","operations":[],"status":"ok"}}\n`
	body := "#!/bin/sh\nwhile IFS= read -r line; do\n" +
		"  id=$(printf '%s' \"$line\" | sed 's/.*\"request_id\":\"\\([^\"]*\\)\".*/\\1/')\n" +
		"  printf '" + answer + "' \"$id\"\ndone\n"
	setup.Check(os.WriteFile(script, []byte(body), 0o700))
	return script
}

func (test *ActorAttributionTest) actors(setup *SesameTestSetup, eventType string) string {
	query := "SELECT actor FROM sesame-security-events WHERE type = '" + eventType + "'"
	root := filepath.Join(setup.deployment, "fylo-root")
	output, err := exec.Command(setup.lookPath("fylo"), "sql", query, "--root", root, "--json").Output()
	setup.Check(err)
	events := map[string]SecurityEventActor{}
	setup.Check(json.Unmarshal(output, &events))
	return test.inOrder(events)
}

func (test *ActorAttributionTest) inOrder(events map[string]SecurityEventActor) string {
	identifiers := make([]string, 0, len(events))
	for identifier := range events {
		identifiers = append(identifiers, identifier)
	}
	sort.Strings(identifiers)
	actors := make([]string, 0, len(identifiers))
	for _, identifier := range identifiers {
		actors = append(actors, events[identifier].Actor)
	}
	return strings.Join(actors, ",")
}

func (test *ActorAttributionTest) principalActor(session sesame.IssuedSession) string {
	return "principal:" + session.TenantID + "/" + session.PrincipalID + "/" + session.SessionID
}

func (test *ActorAttributionTest) creation(tenantID string) PrincipalCreateRequest {
	return PrincipalCreateRequest{TenantID: tenantID, Kind: "human", IdentifierNamespace: "email", IdentifierValue: "created@acme.test"}
}

func (test *ActorAttributionTest) finish(engine *EngineHelper) {
	SesameTestSetup{}.Finish(engine)
}

func (test *ActorAttributionTest) principals(engine *EngineHelper) *PrincipalController {
	return SesameTestSetup{}.Principals(engine, 0)
}
