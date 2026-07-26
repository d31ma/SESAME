package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

// deviceFixture is a tenant with a registered client and an authenticated
// person ready to approve a device.
type deviceFixture struct {
	*flowFixture
	device StartedDeviceAuthorization
}

func newDeviceFixture(t *testing.T) *deviceFixture {
	t.Helper()

	base := newFlowFixture(t)
	ctx := context.Background()

	// Its own client, registered for offline_access, so the grant exercises
	// the refresh path too: a device is exactly the caller that needs to renew
	// without a person present. The flow fixture's client is scoped to
	// "profile" only, and that gate is worth leaving intact.
	registered, err := base.service.ClientRegister(ctx, base.tenantID, "living-room-tv",
		oidcdomain.TypeConfidential, []string{"https://tv.example/cb"},
		[]string{"profile", "offline_access"}, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	base.clientID = registered.Client.ID
	base.secret = registered.Secret

	started, err := base.service.DeviceAuthorizationStart(ctx,
		base.clientID, []string{"profile", "offline_access"}, "test")
	if err != nil {
		t.Fatalf("DeviceAuthorizationStart() error = %v", err)
	}
	return &deviceFixture{flowFixture: base, device: started}
}

// TestDeviceGrantIssuesTokensOnlyAfterApproval walks the whole flow and, more
// importantly, checks the order: polling before approval must not yield
// tokens.
func TestDeviceGrantIssuesTokensOnlyAfterApproval(t *testing.T) {
	t.Parallel()

	fixture := newDeviceFixture(t)
	ctx := context.Background()

	if fixture.device.DeviceCode == "" || fixture.device.UserCode == "" {
		t.Fatalf("device start returned %#v", fixture.device)
	}
	if fixture.device.Interval != oidcdomain.DevicePollInterval {
		t.Fatalf("interval = %d", fixture.device.Interval)
	}

	// Polling before anyone approves is the device's "not yet", and it must
	// be distinguishable from every terminal outcome.
	_, err := fixture.service.TokenExchange(ctx, TokenRequest{
		GrantType:    oidcdomain.GrantTypeDeviceCode,
		DeviceCode:   fixture.device.DeviceCode,
		ClientID:     fixture.clientID,
		ClientSecret: fixture.secret,
	}, "test")
	if !errors.Is(err, ErrDeviceAuthorizationPending) {
		t.Fatalf("polling before approval: err = %v, want ErrDeviceAuthorizationPending", err)
	}

	sessionID, sessionSecret := fixture.login(t)
	if _, err := fixture.service.DeviceAuthorizationApprove(ctx, fixture.tenantID,
		fixture.device.UserCode, sessionID, sessionSecret, "test"); err != nil {
		t.Fatalf("DeviceAuthorizationApprove() error = %v", err)
	}

	tokens, err := fixture.service.TokenExchange(ctx, TokenRequest{
		GrantType:    oidcdomain.GrantTypeDeviceCode,
		DeviceCode:   fixture.device.DeviceCode,
		ClientID:     fixture.clientID,
		ClientSecret: fixture.secret,
	}, "test")
	if err != nil {
		t.Fatalf("TokenExchange() after approval error = %v", err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("device grant returned %#v", tokens)
	}
	// offline_access was requested, so the device can refresh without a
	// person present — which is the point of the grant.
	if tokens.RefreshToken == "" {
		t.Fatal("the device grant carried offline_access but returned no refresh token")
	}
}

// TestDeviceCodeIsSingleUse: a device that replays its code must be refused,
// or a captured code would be worth as much as the tokens it bought.
func TestDeviceCodeIsSingleUse(t *testing.T) {
	t.Parallel()

	fixture := newDeviceFixture(t)
	ctx := context.Background()
	sessionID, sessionSecret := fixture.login(t)
	if _, err := fixture.service.DeviceAuthorizationApprove(ctx, fixture.tenantID,
		fixture.device.UserCode, sessionID, sessionSecret, "test"); err != nil {
		t.Fatalf("DeviceAuthorizationApprove() error = %v", err)
	}

	request := TokenRequest{
		GrantType:    oidcdomain.GrantTypeDeviceCode,
		DeviceCode:   fixture.device.DeviceCode,
		ClientID:     fixture.clientID,
		ClientSecret: fixture.secret,
	}
	if _, err := fixture.service.TokenExchange(ctx, request, "test"); err != nil {
		t.Fatalf("first TokenExchange() error = %v", err)
	}
	if _, err := fixture.service.TokenExchange(ctx, request, "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("replayed device code: err = %v, want ErrInvalidGrant", err)
	}
}

// TestDeviceDenialIsDurableAndOpaque. A refusal must stop the device, and the
// device must not be able to tell refusal from expiry from never-existed —
// otherwise the token endpoint reports on the verification surface.
func TestDeviceDenialIsDurableAndOpaque(t *testing.T) {
	t.Parallel()

	fixture := newDeviceFixture(t)
	ctx := context.Background()

	if err := fixture.service.DeviceAuthorizationDeny(ctx, fixture.tenantID,
		fixture.device.UserCode, "test"); err != nil {
		t.Fatalf("DeviceAuthorizationDeny() error = %v", err)
	}
	_, err := fixture.service.TokenExchange(ctx, TokenRequest{
		GrantType:    oidcdomain.GrantTypeDeviceCode,
		DeviceCode:   fixture.device.DeviceCode,
		ClientID:     fixture.clientID,
		ClientSecret: fixture.secret,
	}, "test")
	if !errors.Is(err, ErrDeviceAccessDenied) {
		t.Fatalf("polling a denied device: err = %v, want ErrDeviceAccessDenied", err)
	}

	// An expired authorization gives the same answer as a denied one.
	other := newDeviceFixture(t)
	other.now = other.now.Add(oidcdomain.DeviceCodeLifetime + time.Second)
	_, err = other.service.TokenExchange(ctx, TokenRequest{
		GrantType:    oidcdomain.GrantTypeDeviceCode,
		DeviceCode:   other.device.DeviceCode,
		ClientID:     other.clientID,
		ClientSecret: other.secret,
	}, "test")
	if !errors.Is(err, ErrDeviceAccessDenied) {
		t.Fatalf("polling an expired device: err = %v, want ErrDeviceAccessDenied", err)
	}
}

// TestApprovingADeviceRequiresAProvedSession is the core authorization
// property: naming a principal is not enough, because a caller that could name
// one could attach any device to anybody.
func TestApprovingADeviceRequiresAProvedSession(t *testing.T) {
	t.Parallel()

	fixture := newDeviceFixture(t)
	ctx := context.Background()
	sessionID, sessionSecret := fixture.login(t)

	for name, attempt := range map[string]struct{ id, secret string }{
		"no session":   {"", ""},
		"unknown id":   {"ses_00000000000000000000000000000000", sessionSecret},
		"wrong secret": {sessionID, "not-the-secret"},
		"empty secret": {sessionID, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.service.DeviceAuthorizationApprove(ctx, fixture.tenantID,
				fixture.device.UserCode, attempt.id, attempt.secret, "test"); err == nil {
				t.Fatal("a device was approved without a proved session")
			}
		})
	}
}

// TestDeviceAuthorizationIsTenantScoped: another tenant must not be able to
// look at, approve, or deny a device waiting in this one.
func TestDeviceAuthorizationIsTenantScoped(t *testing.T) {
	t.Parallel()

	fixture := newDeviceFixture(t)
	ctx := context.Background()
	other, err := fixture.service.Bootstrap(ctx, "other-tenant", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	otherID := other.Tenant.ID

	if _, err := fixture.service.DeviceAuthorizationLookup(otherID,
		fixture.device.UserCode); !errors.Is(err, ErrUserCodeNotFound) {
		t.Fatalf("cross-tenant lookup: err = %v, want ErrUserCodeNotFound", err)
	}
	sessionID, sessionSecret := fixture.login(t)
	if _, err := fixture.service.DeviceAuthorizationApprove(ctx, otherID,
		fixture.device.UserCode, sessionID, sessionSecret,
		"test"); !errors.Is(err, ErrUserCodeNotFound) {
		t.Fatalf("cross-tenant approve: err = %v, want ErrUserCodeNotFound", err)
	}
	if err := fixture.service.DeviceAuthorizationDeny(ctx, otherID,
		fixture.device.UserCode, "test"); !errors.Is(err, ErrUserCodeNotFound) {
		t.Fatalf("cross-tenant deny: err = %v, want ErrUserCodeNotFound", err)
	}
}

// TestDeviceGrantRefusesAnotherClientsCode: the code is bound to the client
// that asked for it, so a second client cannot collect its tokens.
func TestDeviceGrantRefusesAnotherClientsCode(t *testing.T) {
	t.Parallel()

	fixture := newDeviceFixture(t)
	ctx := context.Background()
	sessionID, sessionSecret := fixture.login(t)
	if _, err := fixture.service.DeviceAuthorizationApprove(ctx, fixture.tenantID,
		fixture.device.UserCode, sessionID, sessionSecret, "test"); err != nil {
		t.Fatalf("DeviceAuthorizationApprove() error = %v", err)
	}

	second, err := fixture.service.ClientRegister(ctx, fixture.tenantID, "second-app",
		oidcdomain.TypeConfidential, []string{"https://second.example/cb"},
		[]string{"profile"}, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	if _, err := fixture.service.TokenExchange(ctx, TokenRequest{
		GrantType:    oidcdomain.GrantTypeDeviceCode,
		DeviceCode:   fixture.device.DeviceCode,
		ClientID:     second.Client.ID,
		ClientSecret: second.Secret,
	}, "test"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("another client's device code: err = %v, want ErrInvalidGrant", err)
	}
}

// TestRevokingTheApprovingSessionStopsTheDevice: a person who approves a
// device and then signs out must not have the device collect tokens
// afterwards.
func TestRevokingTheApprovingSessionStopsTheDevice(t *testing.T) {
	t.Parallel()

	fixture := newDeviceFixture(t)
	ctx := context.Background()
	sessionID, sessionSecret := fixture.login(t)
	if _, err := fixture.service.DeviceAuthorizationApprove(ctx, fixture.tenantID,
		fixture.device.UserCode, sessionID, sessionSecret, "test"); err != nil {
		t.Fatalf("DeviceAuthorizationApprove() error = %v", err)
	}
	if err := fixture.service.SessionRevoke(ctx, sessionID, "signed out", "test"); err != nil {
		t.Fatalf("SessionRevoke() error = %v", err)
	}

	if _, err := fixture.service.TokenExchange(ctx, TokenRequest{
		GrantType:    oidcdomain.GrantTypeDeviceCode,
		DeviceCode:   fixture.device.DeviceCode,
		ClientID:     fixture.clientID,
		ClientSecret: fixture.secret,
	}, "test"); !errors.Is(err, ErrDeviceAccessDenied) {
		t.Fatalf("device after sign-out: err = %v, want ErrDeviceAccessDenied", err)
	}
}

// TestSnapshotCarriesDeviceAuthorizations: a device polls across restarts by
// definition, so a projection that forgets one strands it mid-flow.
func TestSnapshotCarriesDeviceAuthorizations(t *testing.T) {
	t.Parallel()

	fixture := newDeviceFixture(t)
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)
	ctx := context.Background()

	sessionID, sessionSecret := fixture.login(t)
	if _, err := fixture.service.DeviceAuthorizationApprove(ctx, fixture.tenantID,
		fixture.device.UserCode, sessionID, sessionSecret, "test"); err != nil {
		t.Fatalf("DeviceAuthorizationApprove() error = %v", err)
	}

	restored, err := NewFromSnapshot(&memoryLedger{}, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	restored.UseIssuer(flowIssuer)
	restored.UseSigningKey(fixture.signingKey)
	restored.UseClock(func() time.Time { return fixture.now })

	tokens, err := restored.TokenExchange(ctx, TokenRequest{
		GrantType:    oidcdomain.GrantTypeDeviceCode,
		DeviceCode:   fixture.device.DeviceCode,
		ClientID:     fixture.clientID,
		ClientSecret: fixture.secret,
	}, "test")
	if err != nil {
		t.Fatalf("a restart stranded an approved device: %v", err)
	}
	if tokens.AccessToken == "" {
		t.Fatal("the restored device grant issued no access token")
	}
}

// TestDeviceAuthorizationsDoNotAccumulate guards a prune that existed but had
// no caller: every authorization ever started stayed in the projection, and in
// every snapshot taken from it, for the life of the process.
func TestDeviceAuthorizationsDoNotAccumulate(t *testing.T) {
	t.Parallel()

	fixture := newDeviceFixture(t)
	for range 3 {
		if _, err := fixture.service.DeviceAuthorizationStart(context.Background(),
			fixture.clientID, []string{"profile"}, "test"); err != nil {
			t.Fatalf("DeviceAuthorizationStart() error = %v", err)
		}
	}
	fixture.service.mu.Lock()
	live := len(fixture.service.deviceAuthorizations)
	fixture.service.mu.Unlock()
	// Three here plus the one the fixture started.
	if live != 4 {
		t.Fatalf("four live authorizations, projection holds %d", live)
	}

	// Retention outlives expiry deliberately, so a device polling just past
	// the deadline is still told it expired rather than that it never existed.
	fixture.now = fixture.now.Add(oidcdomain.DeviceCodeLifetime + deviceAuthorizationRetention +
		time.Second)
	if _, err := fixture.service.DeviceAuthorizationStart(context.Background(),
		fixture.clientID, []string{"profile"}, "test"); err != nil {
		t.Fatalf("DeviceAuthorizationStart() error = %v", err)
	}

	fixture.service.mu.Lock()
	remaining := len(fixture.service.deviceAuthorizations)
	fixture.service.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("authorizations past retention were kept: projection holds %d, want 1", remaining)
	}
}
