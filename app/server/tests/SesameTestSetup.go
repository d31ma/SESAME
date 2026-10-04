import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
	"github.com/d31ma/sesame/app/server/packages/sesame"
)

// @TestSetup
type SesameTestSetup struct {
	directory  string
	binary     string
	deployment string
}

func (SesameTestSetup) Configure(execution *BehaviorExecution) (*BehaviorConfiguration, error) {
	return NewBehaviorConfiguration(), nil
}

func (SesameTestSetup) Provision() *SesameTestSetup {
	setup := &SesameTestSetup{}
	directory, err := os.MkdirTemp("", "sesame-yon-test-*")
	setup.Check(err)
	setup.directory = directory
	setup.binary = setup.lookPath("sesame")
	setup.deployment = filepath.Join(directory, "deployment")
	output, err := exec.Command(setup.binary, "init",
		"--deployment", setup.deployment,
		"--fylo-binary", setup.lookPath("fylo"),
		"--issuer", "https://sesame.test").CombinedOutput()
	setup.checkCommand(err, output)
	setup.UseWait(2000)
	return setup
}

func (setup *SesameTestSetup) UseWait(milliseconds int64) {
	setup.UseSettings(map[string]any{
		"binary":           setup.binary,
		"deployment":       setup.deployment,
		"waitmilliseconds": milliseconds,
	})
}

func (setup *SesameTestSetup) UseSettings(settings map[string]any) {
	encoded, err := json.Marshal(map[string]any{"yon": map[string]any{"sesame": settings}})
	setup.Check(err)
	setup.Check(os.Setenv("YON_APPLICATION_JSON", string(encoded)))
}

func (setup *SesameTestSetup) Remove() {
	setup.Check(os.Unsetenv("YON_APPLICATION_JSON"))
	setup.Check(os.RemoveAll(setup.directory))
}

func (setup *SesameTestSetup) Open() *sesame.Client {
	client, err := sesame.Start(context.Background(), sesame.Options{
		Binary:     setup.binary,
		Deployment: setup.deployment,
	})
	setup.Check(err)
	return client
}

func (setup *SesameTestSetup) CloseLater(client *sesame.Client, delay time.Duration) {
	time.Sleep(delay)
	setup.Check(client.Close())
}

func (setup *SesameTestSetup) SignIn(tenantName string, administrator bool) sesame.IssuedSession {
	return setup.signIn(tenantName, "person", administrator)
}

func (setup *SesameTestSetup) SignInMember(tenantName string, name string) sesame.IssuedSession {
	return setup.signIn(tenantName, name, false)
}

func (setup *SesameTestSetup) signIn(tenantName string, name string, administrator bool) sesame.IssuedSession {
	client := setup.Open()
	defer client.Close()
	ctx := context.Background()
	identifier := sesame.PrincipalIdentifier{Namespace: "email", Value: name + "@" + tenantName + ".test"}
	tenantID, principalID := setup.createPrincipal(client, tenantName, identifier, administrator)
	password := setup.randomText()
	setup.Check(client.SetPassword(ctx, principalID, password))
	started, err := client.AuthenticationBegin(ctx, tenantID, identifier)
	setup.Check(err)
	_, err = client.AuthenticationVerifyPassword(ctx, started.TransactionID, password)
	setup.Check(err)
	session, err := client.AuthenticationComplete(ctx, started.TransactionID, 0)
	setup.Check(err)
	return session
}

func (setup *SesameTestSetup) Revoke(session sesame.IssuedSession) {
	client := setup.Open()
	defer client.Close()
	setup.Check(client.SessionRevoke(context.Background(), session.SessionID, "test"))
}

func (setup *SesameTestSetup) Credential(session sesame.IssuedSession) string {
	return session.SessionID + ":" + session.Secret
}

func (SesameTestSetup) Anonymous() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", nil)
}

func (setup SesameTestSetup) Request(credential string) *http.Request {
	request := setup.Anonymous()
	request.Header.Set("Sesame-Session", credential)
	return request
}

func (setup *SesameTestSetup) SignedIn(session sesame.IssuedSession) *http.Request {
	return setup.Request(setup.Credential(session))
}

func (setup SesameTestSetup) Bearer(token string) *http.Request {
	request := setup.Anonymous()
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

func (SesameTestSetup) Engine() *EngineService {
	return &EngineService{engineSettingsService: &EngineSettingsService{}}
}

func (setup SesameTestSetup) TenantCalls(engine *EngineService) *TenantCallService {
	return setup.TenantCallsAfter(engine, 0)
}

func (SesameTestSetup) TenantCallsAfter(engine *EngineService, elapsed time.Duration) *TenantCallService {
	return &TenantCallService{
		callerService:        &CallerService{engineService: engine},
		engineService:        engine,
		administratorService: &AdministratorService{engineService: engine},
		recentSignInService:  &RecentSignInService{clockShift: elapsed},
	}
}

func (SesameTestSetup) Status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (SesameTestSetup) ProtocolCode(err error) string {
	protocolError := &sesame.ProtocolError{}
	errors.As(err, &protocolError)
	return protocolError.Code
}

func (SesameTestSetup) ErrorCode(err error) string {
	var coded host.CodedError
	if !errors.As(err, &coded) {
		return ""
	}
	return coded.ErrorCode()
}

func (SesameTestSetup) ReauthenticationRequired(err error) bool {
	var required *host.ReauthenticationRequiredError
	return errors.As(err, &required)
}

func (SesameTestSetup) SessionRejected(err error) bool {
	var rejected *host.SessionRejectedError
	return errors.As(err, &rejected)
}

func (SesameTestSetup) RedirectNotAllowed(err error) bool {
	var refusal *host.RedirectNotAllowedError
	return errors.As(err, &refusal)
}

func (setup SesameTestSetup) Encoded(value any) string {
	encoded, err := json.Marshal(value)
	setup.Check(err)
	return string(encoded)
}

func (setup SesameTestSetup) Fields(value any) map[string]any {
	fields := map[string]any{}
	setup.Check(json.Unmarshal([]byte(setup.Encoded(value)), &fields))
	return fields
}

func (setup SesameTestSetup) Segment(value any) string {
	return base64.RawURLEncoding.EncodeToString([]byte(setup.Encoded(value)))
}

func (setup *SesameTestSetup) ScimClient(
	controller *ScimController,
	session sesame.IssuedSession,
	canManageGroups bool,
) ScimClientRegistration {
	registration, err := controller.PostClientRegister(setup.SignedIn(session), setup.ScimRegisterRequest(session.TenantID, canManageGroups))
	setup.Check(err)
	return registration
}

func (SesameTestSetup) ScimRegisterRequest(tenantID string, canManageGroups bool) ScimClientRegisterRequest {
	return ScimClientRegisterRequest{
		TenantID:            tenantID,
		Name:                "directory",
		IdentifierNamespace: "email",
		CanManageGroups:     canManageGroups,
	}
}

func (setup SesameTestSetup) ScimUserCreated(controller *ScimController, token string, userName string) ScimUser {
	user, err := controller.PostUserCreate(setup.Bearer(token), ScimResourceCreateRequest{Body: setup.ScimUserBody(userName)})
	setup.Check(err)
	return user
}

func (setup SesameTestSetup) ScimUserBody(userName string) string {
	return setup.Encoded(map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": userName,
	})
}

func (setup SesameTestSetup) ScimGroupBody(displayName string) string {
	return setup.Encoded(map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": displayName,
	})
}

func (SesameTestSetup) Check(err error) {
	if err != nil {
		panic(err)
	}
}

func (setup *SesameTestSetup) createPrincipal(
	client *sesame.Client,
	tenantName string,
	identifier sesame.PrincipalIdentifier,
	administrator bool,
) (string, string) {
	ctx := context.Background()
	if administrator {
		result, err := client.AdminBootstrap(ctx, tenantName, identifier)
		setup.Check(err)
		return result.Tenant.ID, result.Administrator.ID
	}
	tenant, err := client.TenantBootstrap(ctx, tenantName)
	setup.Check(err)
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	setup.Check(err)
	return tenant.Tenant.ID, principal.ID
}

func (setup *SesameTestSetup) lookPath(name string) string {
	path, err := exec.LookPath(name)
	setup.Check(err)
	absolute, err := filepath.Abs(path)
	setup.Check(err)
	return absolute
}

func (setup *SesameTestSetup) randomText() string {
	value := make([]byte, 24)
	_, err := rand.Read(value)
	setup.Check(err)
	return base64.RawURLEncoding.EncodeToString(value)
}

func (setup *SesameTestSetup) checkCommand(err error, output []byte) {
	if err != nil {
		setup.Check(fmt.Errorf("%w: %s", err, output))
	}
}
