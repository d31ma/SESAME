import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/d31ma/sesame/server/packages/sesame"
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
	setup.check(err)
	setup.directory = directory
	setup.binary = setup.lookPath("sesame")
	setup.deployment = filepath.Join(directory, "deployment")
	output, err := exec.Command(setup.binary, "init",
		"--deployment", setup.deployment,
		"--fylo-binary", setup.lookPath("fylo")).CombinedOutput()
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
	setup.check(err)
	setup.check(os.Setenv("YON_APPLICATION_JSON", string(encoded)))
}

func (setup *SesameTestSetup) Remove() {
	setup.check(os.Unsetenv("YON_APPLICATION_JSON"))
	setup.check(os.RemoveAll(setup.directory))
}

func (setup *SesameTestSetup) Open() *sesame.Client {
	client, err := sesame.Start(context.Background(), sesame.Options{
		Binary:     setup.binary,
		Deployment: setup.deployment,
	})
	setup.check(err)
	return client
}

func (setup *SesameTestSetup) CloseLater(client *sesame.Client, delay time.Duration) {
	time.Sleep(delay)
	setup.check(client.Close())
}

func (setup *SesameTestSetup) SignIn(tenantName string, administrator bool) sesame.IssuedSession {
	client := setup.Open()
	defer client.Close()
	ctx := context.Background()
	identifier := sesame.PrincipalIdentifier{Namespace: "email", Value: "person@" + tenantName + ".test"}
	tenantID, principalID := setup.createPrincipal(client, tenantName, identifier, administrator)
	password := setup.randomText()
	setup.check(client.SetPassword(ctx, principalID, password))
	started, err := client.AuthenticationBegin(ctx, tenantID, identifier)
	setup.check(err)
	_, err = client.AuthenticationVerifyPassword(ctx, started.TransactionID, password)
	setup.check(err)
	session, err := client.AuthenticationComplete(ctx, started.TransactionID, 0)
	setup.check(err)
	return session
}

func (setup *SesameTestSetup) Revoke(session sesame.IssuedSession) {
	client := setup.Open()
	defer client.Close()
	setup.check(client.SessionRevoke(context.Background(), session.SessionID, "test"))
}

func (setup *SesameTestSetup) Credential(session sesame.IssuedSession) string {
	return session.SessionID + ":" + session.Secret
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
		setup.check(err)
		return result.Tenant.ID, result.Administrator.ID
	}
	tenant, err := client.TenantBootstrap(ctx, tenantName)
	setup.check(err)
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	setup.check(err)
	return tenant.Tenant.ID, principal.ID
}

func (setup *SesameTestSetup) lookPath(name string) string {
	path, err := exec.LookPath(name)
	setup.check(err)
	absolute, err := filepath.Abs(path)
	setup.check(err)
	return absolute
}

func (setup *SesameTestSetup) randomText() string {
	value := make([]byte, 24)
	_, err := rand.Read(value)
	setup.check(err)
	return base64.RawURLEncoding.EncodeToString(value)
}

func (setup *SesameTestSetup) checkCommand(err error, output []byte) {
	if err != nil {
		setup.check(fmt.Errorf("%w: %s", err, output))
	}
}

func (setup *SesameTestSetup) check(err error) {
	if err != nil {
		panic(err)
	}
}
