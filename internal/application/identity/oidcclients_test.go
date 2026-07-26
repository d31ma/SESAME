package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

func registerConfidential(t *testing.T, service *Service, tenantID, name string) ClientRegistration {
	t.Helper()

	registered, err := service.ClientRegister(
		context.Background(),
		tenantID,
		name,
		oidcdomain.TypeConfidential,
		[]string{"https://app.example/cb"},
		[]string{"profile"},
		oidcdomain.AudienceFirstParty,
		nil,
		"test",
	)
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	return registered
}

func TestClientRegisterReturnsTheSecretOnce(t *testing.T) {
	t.Parallel()

	service, ledger, tenantID := bootstrapService(t)
	registered := registerConfidential(t, service, tenantID, "Billing Portal")

	if registered.Secret == "" {
		t.Fatal("a confidential client received no secret")
	}
	if registered.Client.Type != oidcdomain.TypeConfidential ||
		strings.Join(registered.Client.Scopes, " ") != "openid profile" {
		t.Fatalf("client = %#v", registered.Client)
	}

	// The secret is not readable afterwards, from the record or the ledger.
	fetched, err := service.ClientGet(registered.Client.ID)
	if err != nil {
		t.Fatalf("ClientGet() error = %v", err)
	}
	if strings.Contains(mustEncode(t, fetched), registered.Secret) {
		t.Fatal("ClientGet returned the client secret")
	}
	for _, event := range ledger.events {
		if strings.Contains(string(event.Payload), registered.Secret) {
			t.Fatalf("event %s carries the plaintext client secret", event.Type)
		}
	}

	// Names are unique per tenant.
	if _, err := service.ClientRegister(context.Background(), tenantID, "Billing Portal",
		oidcdomain.TypePublic, []string{"https://other.example/cb"}, nil, oidcdomain.AudienceFirstParty, nil, "test"); !errors.Is(err, ErrClientExists) {
		t.Fatalf("duplicate ClientRegister() error = %v, want ErrClientExists", err)
	}
}

func TestPublicClientHasNoSecret(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	registered, err := service.ClientRegister(context.Background(), tenantID, "Mobile App",
		oidcdomain.TypePublic, []string{"http://127.0.0.1:8080/cb"}, nil, oidcdomain.AudienceFirstParty, nil, "test")
	if err != nil {
		t.Fatalf("ClientRegister() error = %v", err)
	}
	if registered.Secret != "" {
		t.Fatal("a public client was issued a secret it cannot keep")
	}
	// A public client must not be authenticable by secret at all: an empty
	// secret is not a passing credential.
	if _, err := service.ClientAuthenticate(registered.Client.ID, ""); err == nil {
		t.Fatal("ClientAuthenticate accepted a public client")
	}

	if _, err := service.ClientRotateSecret(context.Background(), registered.Client.ID, "test"); err == nil {
		t.Fatal("ClientRotateSecret issued a secret to a public client")
	}
}

func TestClientAuthenticationAndRotation(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	registered := registerConfidential(t, service, tenantID, "billing")
	ctx := context.Background()

	if _, err := service.ClientAuthenticate(registered.Client.ID, registered.Secret); err != nil {
		t.Fatalf("ClientAuthenticate() error = %v", err)
	}
	if _, err := service.ClientAuthenticate(registered.Client.ID, "wrong"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("ClientAuthenticate with a wrong secret error = %v", err)
	}
	// An unknown client is indistinguishable from a wrong secret.
	unknown, _ := oidcdomain.NewClientID()
	if _, err := service.ClientAuthenticate(unknown, registered.Secret); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("ClientAuthenticate with an unknown client error = %v", err)
	}

	rotated, err := service.ClientRotateSecret(ctx, registered.Client.ID, "test")
	if err != nil {
		t.Fatalf("ClientRotateSecret() error = %v", err)
	}
	if rotated == registered.Secret {
		t.Fatal("ClientRotateSecret returned the same secret")
	}
	// Rotation is only a useful response to a leak if the old secret dies.
	if _, err := service.ClientAuthenticate(registered.Client.ID, registered.Secret); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("the rotated-away secret still authenticates: %v", err)
	}
	if _, err := service.ClientAuthenticate(registered.Client.ID, rotated); err != nil {
		t.Fatalf("ClientAuthenticate with the new secret error = %v", err)
	}
}

func TestClientDisableIsDurableAndIdempotent(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	registered := registerConfidential(t, service, tenantID, "billing")
	ctx := context.Background()

	if err := service.ClientDisable(ctx, registered.Client.ID, "leaked", "test"); err != nil {
		t.Fatalf("ClientDisable() error = %v", err)
	}
	if err := service.ClientDisable(ctx, registered.Client.ID, "leaked", "test"); err != nil {
		t.Fatalf("repeated ClientDisable() error = %v", err)
	}
	if _, err := service.ClientAuthenticate(registered.Client.ID, registered.Secret); !errors.Is(err, ErrClientDisabled) {
		t.Fatalf("a disabled client authenticated: %v", err)
	}
	if _, err := service.ClientRotateSecret(ctx, registered.Client.ID, "test"); !errors.Is(err, ErrClientDisabled) {
		t.Fatalf("a disabled client rotated its secret: %v", err)
	}
}

// TestClientStateSurvivesSnapshotAndReplay is the regression guard for a
// snapshot that forgets the client projection: registration, rotation, and
// disablement must all still hold when the projection is rebuilt either way.
func TestClientStateSurvivesSnapshotAndReplay(t *testing.T) {
	t.Parallel()

	service, ledger, tenantID := bootstrapService(t)
	snapshots := &memorySnapshots{}
	service.UseSnapshots(snapshots)
	ctx := context.Background()

	live := registerConfidential(t, service, tenantID, "live")
	doomed := registerConfidential(t, service, tenantID, "doomed")
	rotated, err := service.ClientRotateSecret(ctx, live.Client.ID, "test")
	if err != nil {
		t.Fatalf("ClientRotateSecret() error = %v", err)
	}
	if err := service.ClientDisable(ctx, doomed.Client.ID, "leaked", "test"); err != nil {
		t.Fatalf("ClientDisable() error = %v", err)
	}

	rebuilt := map[string]*Service{}
	replayed, err := New(&memoryLedger{}, ledger.events)
	if err != nil {
		t.Fatalf("replay New() error = %v", err)
	}
	rebuilt["replay"] = replayed
	seeded, err := NewFromSnapshot(&memoryLedger{}, snapshots.states[len(snapshots.states)-1], nil)
	if err != nil {
		t.Fatalf("NewFromSnapshot() error = %v", err)
	}
	rebuilt["snapshot"] = seeded

	for kind, restored := range rebuilt {
		if _, err := restored.ClientAuthenticate(live.Client.ID, rotated); err != nil {
			t.Fatalf("%s: the rotated secret does not authenticate: %v", kind, err)
		}
		if _, err := restored.ClientAuthenticate(live.Client.ID, live.Secret); !errors.Is(err, ErrClientNotFound) {
			t.Fatalf("%s: the pre-rotation secret survived: %v", kind, err)
		}
		if _, err := restored.ClientAuthenticate(doomed.Client.ID, doomed.Secret); !errors.Is(err, ErrClientDisabled) {
			t.Fatalf("%s: the disabled client authenticated: %v", kind, err)
		}
	}

	// The snapshot itself must not carry a usable secret.
	encoded := string(snapshots.states[len(snapshots.states)-1])
	for _, secret := range []string{live.Secret, doomed.Secret, rotated} {
		if strings.Contains(encoded, secret) {
			t.Fatal("the snapshot carries a plaintext client secret")
		}
	}
}

func TestClientRegisterValidatesAtTheBoundary(t *testing.T) {
	t.Parallel()

	service, _, tenantID := bootstrapService(t)
	ctx := context.Background()

	cases := map[string]struct {
		name         string
		clientType   string
		redirectURIs []string
		scopes       []string
	}{
		"no redirect":       {"a", oidcdomain.TypePublic, nil, nil},
		"wildcard redirect": {"a", oidcdomain.TypePublic, []string{"https://*.example/cb"}, nil},
		"plain http":        {"a", oidcdomain.TypePublic, []string{"http://app.example/cb"}, nil},
		"bad type":          {"a", "native", []string{"https://app.example/cb"}, nil},
		"empty name":        {"", oidcdomain.TypePublic, []string{"https://app.example/cb"}, nil},
		"bad scope":         {"a", oidcdomain.TypePublic, []string{"https://app.example/cb"}, []string{"has space"}},
	}
	for label, testCase := range cases {
		if _, err := service.ClientRegister(ctx, tenantID, testCase.name, testCase.clientType,
			testCase.redirectURIs, testCase.scopes, oidcdomain.AudienceFirstParty, nil, "test"); err == nil {
			t.Fatalf("ClientRegister accepted %s", label)
		}
	}

	// A client cannot be attached to a tenant that does not exist.
	if _, err := service.ClientRegister(ctx, "tnt_00000000000000000000000000000000", "a",
		oidcdomain.TypePublic, []string{"https://app.example/cb"}, nil, oidcdomain.AudienceFirstParty, nil, "test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ClientRegister into an unknown tenant error = %v", err)
	}
}
