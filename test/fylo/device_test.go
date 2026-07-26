package fylo_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

// TestRealFYLODeviceGrantSurvivesRestart proves against a real FYLO runtime
// that a device polling across a restart is not stranded.
//
// This grant is the one where restart durability is not a nice property but
// the whole shape of the flow: a device sits polling for minutes while a
// person walks to another room, and any restart in that window falls inside
// the flow rather than between flows. Three things have to replay or the
// grant is broken — the pending authorization with its user code, an approval
// that has already happened, and the single-use claim on a spent device code.
func TestRealFYLODeviceGrantSurvivesRestart(t *testing.T) {
	if os.Getenv("SESAME_FYLO_INTEGRATION") != "1" {
		t.Skip("set SESAME_FYLO_INTEGRATION=1 to test a real FYLO runtime")
	}
	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		binary = "fylo"
	}
	config := fyloadapter.Config{
		Binary:                 binary,
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	root, err := os.MkdirTemp("", "sesame-device-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	config.Root = filepath.Join(root, "db")
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	const (
		issuer   = "https://id.example.com"
		password = "correct horse battery staple"
	)
	now := time.Unix(1_700_000_000, 0).UTC()

	secretsKey := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	if _, err := rand.Read(secretsKey); err != nil {
		t.Fatalf("generate secrets key: %v", err)
	}
	signing, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}

	open := func() (*fyloadapter.Client, *identityapp.Service) {
		t.Helper()
		client, err := fyloadapter.Start(ctx, config)
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		ledger, events, err := securityledger.Open(ctx, client)
		if err != nil {
			t.Fatalf("Open() error = %v", err)
		}
		service, err := identityapp.New(ledger, events)
		if err != nil {
			t.Fatalf("identity.New() error = %v", err)
		}
		service.UseSecretsKey(secretsKey)
		service.UseSigningKey(signing)
		service.UseIssuer(issuer)
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "tv-co", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "viewer@example.com"}
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID,
		principaldomain.KindHuman, identifier, "test:integration")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	if err := service.PasswordSet(ctx, principal.ID, password, "test:integration"); err != nil {
		t.Fatalf("PasswordSet() error = %v", err)
	}
	registered, err := service.ClientRegister(ctx, tenant.Tenant.ID, "living-room-tv",
		oidcdomain.TypePublic, []string{"https://tv.example/cb"},
		[]string{"profile"}, oidcdomain.AudienceFirstParty, nil, "test:integration")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}

	// One device is left pending across the restart; a second is approved and
	// redeemed, so the spent claim has to replay too.
	pending, err := service.DeviceAuthorizationStart(ctx, registered.Client.ID,
		[]string{"profile"}, "test:integration")
	if err != nil {
		t.Fatalf("DeviceAuthorizationStart() error = %v", err)
	}
	spent, err := service.DeviceAuthorizationStart(ctx, registered.Client.ID,
		[]string{"profile"}, "test:integration")
	if err != nil {
		t.Fatalf("DeviceAuthorizationStart() error = %v", err)
	}

	login := func(service *identityapp.Service) (string, string) {
		t.Helper()
		begun, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test:integration")
		if err != nil {
			t.Fatalf("AuthenticationBegin() error = %v", err)
		}
		if _, err := service.AuthenticationVerifyPassword(ctx, begun.TransactionID,
			password, "test:integration"); err != nil {
			t.Fatalf("AuthenticationVerifyPassword() error = %v", err)
		}
		issued, err := service.AuthenticationComplete(ctx, begun.TransactionID,
			time.Hour, "test:integration")
		if err != nil {
			t.Fatalf("AuthenticationComplete() error = %v", err)
		}
		return issued.SessionID, issued.Secret
	}

	sessionID, sessionSecret := login(service)
	if _, err := service.DeviceAuthorizationApprove(ctx, tenant.Tenant.ID,
		spent.UserCode, sessionID, sessionSecret, "test:integration"); err != nil {
		t.Fatalf("DeviceAuthorizationApprove() error = %v", err)
	}
	spentRequest := identityapp.TokenRequest{
		GrantType:  oidcdomain.GrantTypeDeviceCode,
		DeviceCode: spent.DeviceCode,
		ClientID:   registered.Client.ID,
	}
	if _, err := service.TokenExchange(ctx, spentRequest, "test:integration"); err != nil {
		t.Fatalf("TokenExchange() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// ---- restart ----
	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	// The pending authorization replays with its user code intact, so the
	// person who is halfway to their phone can still approve it.
	looked, err := replayed.DeviceAuthorizationLookup(tenant.Tenant.ID, pending.UserCode)
	if err != nil {
		t.Fatalf("a restart forgot a pending device: %v", err)
	}
	if looked.ClientName != "living-room-tv" {
		t.Fatalf("restored lookup = %#v", looked)
	}

	// And it still polls as pending rather than as unknown.
	pendingRequest := identityapp.TokenRequest{
		GrantType:  oidcdomain.GrantTypeDeviceCode,
		DeviceCode: pending.DeviceCode,
		ClientID:   registered.Client.ID,
	}
	if _, err := replayed.TokenExchange(ctx, pendingRequest,
		"test:integration"); !errors.Is(err, identityapp.ErrDeviceAuthorizationPending) {
		t.Fatalf("a restarted pending device polled as %v, want ErrDeviceAuthorizationPending", err)
	}

	// The spent device code is still spent. This is the claim that matters
	// most: a restart that forgot it would make a captured device code
	// redeemable a second time.
	if _, err := replayed.TokenExchange(ctx, spentRequest,
		"test:integration"); !errors.Is(err, identityapp.ErrInvalidGrant) {
		t.Fatalf("a restart forgot a spent device code: %v", err)
	}

	// The pending one can still be carried to completion after the restart.
	restartSessionID, restartSessionSecret := login(replayed)
	if _, err := replayed.DeviceAuthorizationApprove(ctx, tenant.Tenant.ID,
		pending.UserCode, restartSessionID, restartSessionSecret, "test:integration"); err != nil {
		t.Fatalf("DeviceAuthorizationApprove() after restart error = %v", err)
	}
	tokens, err := replayed.TokenExchange(ctx, pendingRequest, "test:integration")
	if err != nil {
		t.Fatalf("TokenExchange() after restart error = %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("the restored device grant issued no access token")
	}
}
