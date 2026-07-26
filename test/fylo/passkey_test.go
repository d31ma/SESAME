package fylo_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

type passkeyDevice struct {
	key          *ecdsa.PrivateKey
	publicPoint  []byte
	credentialID []byte
	signCount    uint32
}

func cborHead(major byte, argument uint64) []byte {
	switch {
	case argument < 24:
		return []byte{major<<5 | byte(argument)}
	case argument < 1<<8:
		return []byte{major<<5 | 24, byte(argument)}
	default:
		return []byte{major<<5 | 25, byte(argument >> 8), byte(argument)}
	}
}

func (d *passkeyDevice) cose() []byte {
	x := d.publicPoint[1:33]
	y := d.publicPoint[33:]
	out := cborHead(5, 5)
	out = append(out, cborHead(0, 1)...)
	out = append(out, cborHead(0, 2)...)
	out = append(out, cborHead(0, 3)...)
	out = append(out, cborHead(1, 6)...)
	out = append(out, cborHead(1, 0)...)
	out = append(out, cborHead(0, 1)...)
	out = append(out, cborHead(1, 1)...)
	out = append(out, append(cborHead(2, 32), x...)...)
	out = append(out, cborHead(1, 2)...)
	out = append(out, append(cborHead(2, 32), y...)...)
	return out
}

func (d *passkeyDevice) authData(rpID string, flags byte, withCredential bool) []byte {
	hash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, hash[:]...)
	out = append(out, flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, d.signCount)
	out = append(out, counter...)
	if !withCredential {
		return out
	}
	out = append(out, make([]byte, 16)...)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(d.credentialID)))
	out = append(out, length...)
	out = append(out, d.credentialID...)
	out = append(out, d.cose()...)
	return out
}

func (d *passkeyDevice) attestation(rpID string) []byte {
	body := d.authData(rpID, 0x01|0x04|0x40, true)
	out := cborHead(5, 3)
	out = append(out, append(cborHead(3, 3), []byte("fmt")...)...)
	out = append(out, append(cborHead(3, 4), []byte("none")...)...)
	out = append(out, append(cborHead(3, 7), []byte("attStmt")...)...)
	out = append(out, cborHead(5, 0)...)
	out = append(out, append(cborHead(3, 8), []byte("authData")...)...)
	out = append(out, append(cborHead(2, uint64(len(body))), body...)...)
	return out
}

func passkeyClientData(t *testing.T, dataType, challenge, origin string) []byte {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{
		"type": dataType, "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

// TestRealFYLOPasskeyCloneDetectedAcrossRestart proves against a real FYLO
// runtime that an advanced sign counter is durable. A restart that lost it
// would silently disable clone detection — the one signal WebAuthn gives that
// a credential has been copied out of its authenticator.
func TestRealFYLOPasskeyCloneDetectedAcrossRestart(t *testing.T) {
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
	root, err := os.MkdirTemp("", "sesame-passkey-*")
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

	const issuer = "https://id.example"
	now := time.Unix(1_700_000_000, 0).UTC()

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
		service.UseIssuer(issuer)
		service.UseClock(func() time.Time { return now })
		return client, service
	}

	client, service := open()
	tenant, err := service.Bootstrap(ctx, "acme", "test:integration")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "passkey@example.com"}
	principal, err := service.PrincipalCreate(
		ctx, tenant.Tenant.ID, principaldomain.KindHuman, identifier, "test:integration")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	device := &passkeyDevice{
		key:          key,
		publicPoint:  mustPublicPoint(t, key),
		credentialID: make([]byte, 20),
	}
	if _, err := rand.Read(device.credentialID); err != nil {
		t.Fatalf("rand: %v", err)
	}

	begun, err := service.PasskeyRegisterBegin(principal.ID)
	if err != nil {
		t.Fatalf("PasskeyRegisterBegin() error = %v", err)
	}
	stored, err := service.PasskeyRegisterFinish(ctx, principal.ID,
		device.attestation(begun.RelyingPartyID),
		passkeyClientData(t, "webauthn.create", begun.Challenge, begun.Origin), "test:integration")
	if err != nil {
		t.Fatalf("PasskeyRegisterFinish() error = %v", err)
	}

	authenticate := func(service *identityapp.Service, counter uint32) identityapp.AuthenticationResult {
		t.Helper()
		transaction, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test:integration")
		if err != nil {
			t.Fatalf("AuthenticationBegin() error = %v", err)
		}
		options, err := service.PasskeyAuthenticationOptions(transaction.TransactionID)
		if err != nil {
			t.Fatalf("PasskeyAuthenticationOptions() error = %v", err)
		}
		device.signCount = counter
		data := device.authData(options.RelyingPartyID, 0x01|0x04, false)
		clientData := passkeyClientData(t, "webauthn.get", options.Challenge, options.Origin)
		clientHash := sha256.Sum256(clientData)
		digest := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
		signature, err := ecdsa.SignASN1(rand.Reader, device.key, digest[:])
		if err != nil {
			t.Fatalf("SignASN1: %v", err)
		}
		result, err := service.AuthenticationVerifyPasskey(ctx, transaction.TransactionID,
			stored.CredentialID, data, clientData, signature, "test:integration")
		if err != nil {
			t.Fatalf("AuthenticationVerifyPasskey() error = %v", err)
		}
		return result
	}

	if result := authenticate(service, 7); result.Assurance != "mfa" {
		t.Fatalf("a user-verified passkey did not establish mfa: %#v", result)
	}

	// Kill the process the way a crash would.
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	restarted, replayed := open()
	t.Cleanup(func() { _ = restarted.Close() })

	// The counter survived, so a clone replaying an older one is caught.
	if result := authenticate(replayed, 5); result.Assurance != "" {
		t.Fatalf("a cloned counter authenticated after restart: %#v", result)
	}
	// And a genuine advance still works.
	if result := authenticate(replayed, 9); result.Assurance != "mfa" {
		t.Fatalf("a genuine assertion failed after restart: %#v", result)
	}

	keys, err := replayed.PasskeyList(principal.ID)
	if err != nil || len(keys) != 1 || keys[0].SignCount != 9 {
		t.Fatalf("PasskeyList() = %#v, %v", keys, err)
	}
}
