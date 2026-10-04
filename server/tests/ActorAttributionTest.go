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

	"github.com/d31ma/sesame/server/packages/sesame"
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
	engine := test.engine()

	_, err := test.principals(engine).PostSuspend(test.request(setup.Credential(administrator)), PrincipalReference{PrincipalID: member.PrincipalID})
	test.finish(engine)

	Assert.IsTrue(err == nil)
	Assert.Equals(test.principalActor(administrator), test.actors(setup, "principal.suspended"))
}

func (test *ActorAttributionTest) TestSelfServiceWriteRecordsTheCallingPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	member := setup.SignInMember("acme", "member")
	engine := test.engine()
	sessions := &SessionController{callerService: &CallerService{engineService: engine}, engineService: engine}

	_, err := sessions.PostRevoke(test.request(setup.Credential(member)), SessionRevokeReason{Reason: "signed_out"})
	test.finish(engine)

	Assert.IsTrue(err == nil)
	Assert.Equals(test.principalActor(member), test.actors(setup, "session.revoked"))
}

func (test *ActorAttributionTest) TestGrantRevokeRecordsTheCallingPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	engine := test.engine()
	callers := &CallerService{engineService: engine}
	calls := &TenantCallService{callerService: callers, engineService: engine}
	grants := &GrantController{tenantCallService: calls, callerService: callers, engineService: engine}
	request := test.request(setup.Credential(administrator))
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
	engine := test.engine()
	sessions := &SessionController{callerService: &CallerService{engineService: engine}, engineService: engine}

	_, err := sessions.PostRevokeByID(test.request(setup.Credential(administrator)), SessionRevokeRequest{SessionID: other.SessionID})
	test.finish(engine)

	Assert.Equals(http.StatusForbidden, (&SesameErrorHandler{}).Answer(err).StatusCode)
	Assert.Equals("", test.actors(setup, "session.revoked"))
}

func (test *ActorAttributionTest) TestCallActsAsTheBoundCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	engine := test.engine()

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
	engine := test.engine()

	err := engine.Call("principal.create", test.creation(administrator.TenantID), &Principal{})
	test.finish(engine)

	Assert.IsTrue(err == nil)
	Assert.Equals("operator:machine,operator:machine", test.actors(setup, "principal.created"))
}

func (test *ActorAttributionTest) TestRejectedCallerBindsNoActor() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	engine := test.engine()

	_, rejected := (&CallerService{engineService: engine}).Resolve(httptest.NewRequest(http.MethodPost, "/", nil))
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
	bound := test.engine()
	unbound := test.engine()

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
	setup.check(os.WriteFile(script, []byte(body), 0o700))
	return script
}

func (test *ActorAttributionTest) actors(setup *SesameTestSetup, eventType string) string {
	query := "SELECT actor FROM sesame-security-events WHERE type = '" + eventType + "'"
	root := filepath.Join(setup.deployment, "fylo-root")
	output, err := exec.Command(setup.lookPath("fylo"), "sql", query, "--root", root, "--json").Output()
	setup.check(err)
	events := map[string]SecurityEventActor{}
	setup.check(json.Unmarshal(output, &events))
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

func (test *ActorAttributionTest) request(credential string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (test *ActorAttributionTest) finish(engine *EngineService) {
	if engine.client != nil {
		engine.client.Close()
	}
}

func (test *ActorAttributionTest) principals(engine *EngineService) *PrincipalController {
	callers := &CallerService{engineService: engine}
	return &PrincipalController{
		tenantCallService:      &TenantCallService{callerService: callers, engineService: engine},
		principalTenantService: &PrincipalTenantService{callerService: callers, engineService: engine},
	}
}

func (test *ActorAttributionTest) engine() *EngineService {
	return &EngineService{engineSettingsService: &EngineSettingsService{}}
}
