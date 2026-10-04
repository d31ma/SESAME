package sesame

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const actorProbeSource = `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

var requestFields string

type frame struct {
	RequestID string          ` + "`json:\"request_id\"`" + `
	Operation string          ` + "`json:\"operation\"`" + `
	Actor     json.RawMessage ` + "`json:\"actor\"`" + `
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	received := 0
	for scanner.Scan() {
		var request frame
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			continue
		}
		switch request.Operation {
		case "system.version":
			fields := "[]"
			if requestFields != "" {
				fields = fmt.Sprintf("[%q]", requestFields)
			}
			fmt.Printf("{\"protocol_version\":\"1\",\"request_id\":%q,\"ok\":true,\"result\":{\"name\":\"sesame\",\"version\":\"probe\",\"protocol_version\":\"1\",\"operations\":[],\"request_fields\":%s}}\n", request.RequestID, fields)
		case "probe.refuse":
			received++
			fmt.Printf("{\"protocol_version\":\"1\",\"request_id\":%q,\"ok\":false,\"error\":{\"code\":\"actor_tenant_mismatch\",\"message\":\"refused\",\"retryable\":false}}\n", request.RequestID)
		default:
			received++
			actor := "null"
			if len(request.Actor) != 0 {
				actor = string(request.Actor)
			}
			fmt.Printf("{\"protocol_version\":\"1\",\"request_id\":%q,\"ok\":true,\"result\":{\"actor\":%s,\"received\":%d}}\n", request.RequestID, actor, received)
		}
	}
}
`

type actorProbeAnswer struct {
	Actor    json.RawMessage `json:"actor"`
	Received int             `json:"received"`
}

func buildActorProbe(t *testing.T, requestFields string) string {
	t.Helper()
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "main.go"), []byte(actorProbeSource), 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "go.mod"), []byte("module probe\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatalf("write probe module: %v", err)
	}
	probe := filepath.Join(workspace, "probe")
	if runtime.GOOS == "windows" {
		probe += ".exe"
	}
	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-X main.requestFields="+requestFields, "-o", probe, ".")
	build.Dir = workspace
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=auto", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v\n%s", err, output)
	}
	return probe
}

func startActorProbe(t *testing.T, requestFields string, options Options) *Client {
	t.Helper()
	options.Binary = buildActorProbe(t, requestFields)
	client, err := Start(context.Background(), options)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func probeActor(t *testing.T, client *Client, ctx context.Context, operation string) actorProbeAnswer {
	t.Helper()
	var answer actorProbeAnswer
	if err := client.Request(ctx, operation, struct{}{}, &answer); err != nil {
		t.Fatalf("Request(%s) error = %v", operation, err)
	}
	return answer
}

func probeIdentity() Actor {
	return Actor{
		TenantID:    "tnt_00000000000000000000000000000001",
		PrincipalID: "prn_00000000000000000000000000000002",
		SessionID:   "ses_00000000000000000000000000000003",
	}
}

func TestRequestSendsTheActorWhenTheEngineAcceptsIt(t *testing.T) {
	t.Parallel()
	client := startActorProbe(t, "actor", Options{})

	answer := probeActor(t, client, WithActor(context.Background(), probeIdentity()), "probe.echo")

	want := `{"tenant_id":"tnt_00000000000000000000000000000001","principal_id":"prn_00000000000000000000000000000002","session_id":"ses_00000000000000000000000000000003"}`
	if string(answer.Actor) != want {
		t.Fatalf("actor = %s, want %s", answer.Actor, want)
	}
}

func TestRequestOmitsTheActorWithoutOne(t *testing.T) {
	t.Parallel()
	client := startActorProbe(t, "actor", Options{})

	answer := probeActor(t, client, context.Background(), "probe.echo")

	if string(answer.Actor) != "null" {
		t.Fatalf("actor = %s, want it omitted", answer.Actor)
	}
}

func TestRequestOmitsTheActorWhenTheEngineDoesNotListIt(t *testing.T) {
	t.Parallel()
	client := startActorProbe(t, "", Options{})

	answer := probeActor(t, client, WithActor(context.Background(), probeIdentity()), "probe.echo")

	if string(answer.Actor) != "null" {
		t.Fatalf("actor = %s, want it omitted", answer.Actor)
	}
}

func TestRequestOmitsTheActorWhenTheHandshakeWasSkipped(t *testing.T) {
	t.Parallel()
	client := startActorProbe(t, "actor", Options{SkipCompatibilityCheck: true})

	answer := probeActor(t, client, WithActor(context.Background(), probeIdentity()), "probe.echo")

	if string(answer.Actor) != "null" {
		t.Fatalf("actor = %s, want it omitted", answer.Actor)
	}
}

func TestRequestNeverSendsTheActorToStandardsDispatch(t *testing.T) {
	t.Parallel()
	client := startActorProbe(t, "actor", Options{})

	answer := probeActor(t, client, WithActor(context.Background(), probeIdentity()), "standards.dispatch")

	if string(answer.Actor) != "null" {
		t.Fatalf("actor = %s, want it omitted", answer.Actor)
	}
}

func TestRequestDoesNotRetryAnActorRefusal(t *testing.T) {
	t.Parallel()
	client := startActorProbe(t, "actor", Options{})
	ctx := WithActor(context.Background(), probeIdentity())

	err := client.Request(ctx, "probe.refuse", struct{}{}, &actorProbeAnswer{})
	answer := probeActor(t, client, ctx, "probe.echo")

	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code != codeActorTenantMismatch {
		t.Fatalf("Request(probe.refuse) error = %v", err)
	}
	if answer.Received != 2 {
		t.Fatalf("engine received %d requests, want 2 (one refusal, one echo)", answer.Received)
	}
}

func TestVersionReportsTheRequestFields(t *testing.T) {
	t.Parallel()
	client, err := Start(context.Background(), Options{Binary: testBinary})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	info, err := client.Version(context.Background())

	if err != nil || len(info.RequestFields) != 1 || info.RequestFields[0] != "actor" {
		t.Fatalf("Version() = %#v, %v", info.RequestFields, err)
	}
}

func TestTheEngineChecksTheActor(t *testing.T) {
	t.Parallel()
	client := startStorageBackedEngine(t)
	ctx, cancel := context.WithTimeout(context.Background(), testOperationTimeout)
	defer cancel()
	session := signInToNewTenant(t, client, ctx, "actor-acme")
	actor := Actor{TenantID: session.TenantID, PrincipalID: session.PrincipalID, SessionID: session.SessionID}
	other, err := client.TenantBootstrap(ctx, "actor-globex")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	identifier := PrincipalIdentifier{Namespace: "email", Value: "member@example.com"}

	_, ownTenant := client.PrincipalCreate(WithActor(ctx, actor), session.TenantID, "human", identifier)
	_, otherTenant := client.PrincipalCreate(WithActor(ctx, actor), other.Tenant.ID, "human", identifier)
	_, unknownSession := client.PrincipalCreate(WithActor(ctx, probeIdentity()), session.TenantID, "human", identifier)

	if ownTenant != nil {
		t.Fatalf("PrincipalCreate(own tenant) error = %v", ownTenant)
	}
	requireProtocolCode(t, otherTenant, codeActorTenantMismatch)
	requireProtocolCode(t, unknownSession, codeActorSessionInvalid)
}

func requireProtocolCode(t *testing.T, err error, code string) {
	t.Helper()
	var protocolError *ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code != code || protocolError.Retryable {
		t.Fatalf("error = %v, want non-retryable %s", err, code)
	}
}

func startStorageBackedEngine(t *testing.T) *Client {
	t.Helper()
	workspace := t.TempDir()
	root := filepath.Join(workspace, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	client, err := Start(context.Background(), Options{
		Binary:     testBinary,
		FYLOBinary: buildFakeFYLO(t, workspace),
		FYLORoot:   root,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func signInToNewTenant(t *testing.T, client *Client, ctx context.Context, tenantName string) IssuedSession {
	t.Helper()
	tenant, err := client.TenantBootstrap(ctx, tenantName)
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	identifier := PrincipalIdentifier{Namespace: "email", Value: "actor@example.com"}
	principal, err := client.PrincipalCreate(ctx, tenant.Tenant.ID, "human", identifier)
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	const password = "correct horse battery staple"
	if err := client.SetPassword(ctx, principal.ID, password); err != nil {
		t.Fatalf("SetPassword() error = %v", err)
	}
	begun, err := client.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier)
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	if _, err := client.AuthenticationVerifyPassword(ctx, begun.TransactionID, password); err != nil {
		t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
	}
	session, err := client.AuthenticationComplete(ctx, begun.TransactionID, 0)
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	return session
}

func TestRequireActorAcceptsAnEngineThatListsIt(t *testing.T) {
	t.Parallel()
	client := startActorProbe(t, "actor", Options{})

	if err := client.RequireActor(); err != nil {
		t.Fatalf("RequireActor() error = %v", err)
	}
}

func TestRequireActorNamesTheMissingField(t *testing.T) {
	t.Parallel()
	client := startActorProbe(t, "", Options{})

	err := client.RequireActor()

	var incompatible *IncompatibleEngineError
	if !errors.As(err, &incompatible) || len(incompatible.MissingRequestFields) != 1 || incompatible.MissingRequestFields[0] != "actor" {
		t.Fatalf("RequireActor() error = %#v", err)
	}
	if incompatible.EngineVersion != "probe" || !strings.Contains(err.Error(), `"actor"`) {
		t.Fatalf("RequireActor() error = %v", err)
	}
}
