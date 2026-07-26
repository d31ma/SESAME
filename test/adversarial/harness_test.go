// Package adversarial_test is SESAME's protocol adversarial suite.
//
// It is not a unit-test mirror. Every attack here runs against a real compiled
// `sesame` binary over the shipped machine protocol, through the shipped Go
// SDK, against a real deployment directory with real keys — so a defence that
// exists only inside a package boundary, or only when a test constructs the
// service by hand, does not count.
//
// Each case is named for the attack rather than the function, because the
// question a reader has is "does SESAME resist X", not "does function Y
// return an error".
package adversarial_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/d31ma/sesame/clients/go/sesame"
)

const (
	issuer      = "https://id.example"
	redirectURI = "https://app.example/cb"
	logoutURI   = "https://app.example/bye"
	verifier    = "sesame-adversarial-verifier-0123456789-abcdef"
	password    = "correct horse battery staple"
	timeout     = 30 * time.Second
)

var (
	sesameBinary string
	fyloBinary   string
)

func challenge() string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestMain(m *testing.M) {
	workspace, err := os.MkdirTemp("", "sesame-adversarial-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create workspace: %v\n", err)
		os.Exit(1)
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "locate adversarial suite")
		os.Exit(1)
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))

	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	sesameBinary = filepath.Join(workspace, "sesame"+suffix)
	fyloBinary = filepath.Join(workspace, "fake-fylo"+suffix)
	for target, output := range map[string]string{
		"./cmd/sesame": sesameBinary,
		"./internal/adapters/fylo/testdata/fakefylo": fyloBinary,
	} {
		build := exec.Command("go", "build", "-trimpath", "-o", output, target)
		build.Dir = root
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto")
		if out, err := build.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s", target, err, out)
			os.Exit(1)
		}
	}

	code := m.Run()
	_ = os.RemoveAll(workspace)
	os.Exit(code)
}

// deployment is one adversarial scenario: a real binary over a real deployment
// with a tenant, a principal with a password, and a registered client.
type deployment struct {
	// directory is the deployment root, so a test can inspect what actually
	// landed on disk rather than only what the protocol returned.
	directory   string
	client      *sesame.Client
	tenantID    string
	principalID string
	clientID    string
	secret      string
	identifier  sesame.PrincipalIdentifier
}

func newDeployment(t *testing.T) *deployment {
	t.Helper()

	workspace := t.TempDir()
	directory := filepath.Join(workspace, "deploy")
	initialize := exec.Command(sesameBinary, "init",
		"--deployment", directory, "--fylo-binary", fyloBinary, "--issuer", issuer)
	if output, err := initialize.CombinedOutput(); err != nil {
		t.Fatalf("sesame init: %v\n%s", err, output)
	}

	client, err := sesame.Start(context.Background(), sesame.Options{
		Binary:     sesameBinary,
		Deployment: directory,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tenant, err := client.TenantBootstrap(ctx, "adversarial")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	identifier := sesame.PrincipalIdentifier{Namespace: "email", Value: "victim@example.com"}
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := client.SetPassword(ctx, principal.ID, password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	registered, err := client.ClientRegister(ctx, tenant.Tenant.ID, "victim-app", "confidential",
		[]string{redirectURI}, []string{"profile", "offline_access"}, "first_party", []string{logoutURI})
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	return &deployment{
		directory:   directory,
		client:      client,
		tenantID:    tenant.Tenant.ID,
		principalID: principal.ID,
		clientID:    registered.Client.ID,
		secret:      registered.Secret,
		identifier:  identifier,
	}
}

func (d *deployment) login(t *testing.T) sesame.IssuedSession {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	begun, err := d.client.AuthenticationBegin(ctx, d.tenantID, d.identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := d.client.AuthenticationVerifyPassword(ctx, begun.TransactionID, password); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := d.client.AuthenticationComplete(ctx, begun.TransactionID, 0)
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	return session
}

// authorize runs one browser flow to a fresh authorization code.
func (d *deployment) authorize(t *testing.T, session sesame.IssuedSession) sesame.AuthorizationResponse {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	started, err := d.client.Authorize(ctx, sesame.AuthorizationRequest{
		ClientID:            d.clientID,
		RedirectURI:         redirectURI,
		ResponseType:        "code",
		Scopes:              []string{"openid", "offline_access"},
		State:               "client-state",
		Nonce:               "client-nonce",
		CodeChallenge:       challenge(),
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	response, err := d.client.InteractionComplete(ctx, started.InteractionID, started.Secret,
		session.SessionID, session.Secret)
	if err != nil {
		t.Fatalf("InteractionComplete() error = %v", err)
	}
	return response
}

func (d *deployment) tokenRequest(code string) sesame.TokenRequest {
	return sesame.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  redirectURI,
		ClientID:     d.clientID,
		ClientSecret: d.secret,
		CodeVerifier: verifier,
	}
}

// refused asserts the engine rejected an attack with a specific stable code.
func refused(t *testing.T, attack string, err error, code string) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s SUCCEEDED; the engine accepted it", attack)
	}
	var protocolError *sesame.ProtocolError
	if !errors.As(err, &protocolError) {
		t.Fatalf("%s was refused with a non-protocol error %T %v", attack, err, err)
	}
	if protocolError.Code != code {
		t.Fatalf("%s was refused with %q, want %q", attack, protocolError.Code, code)
	}
}
