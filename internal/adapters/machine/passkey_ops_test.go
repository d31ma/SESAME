package machine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/application/identity"
	"github.com/d31ma/sesame/internal/application/system"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	"github.com/d31ma/sesame/internal/platform/buildinfo"
)

// edgeDevice produces real WebAuthn wire formats over the machine protocol.
type edgeDevice struct {
	key          *ecdsa.PrivateKey
	publicPoint  []byte
	credentialID []byte
	signCount    uint32
}

func newEdgeDevice(t *testing.T) *edgeDevice {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	id := make([]byte, 20)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return &edgeDevice{key: key, publicPoint: mustPublicPoint(t, key), credentialID: id}
}

func cborItem(major byte, argument uint64) []byte {
	switch {
	case argument < 24:
		return []byte{major<<5 | byte(argument)}
	case argument < 1<<8:
		return []byte{major<<5 | 24, byte(argument)}
	default:
		return []byte{major<<5 | 25, byte(argument >> 8), byte(argument)}
	}
}

func (d *edgeDevice) cose() []byte {
	x := d.publicPoint[1:33]
	y := d.publicPoint[33:]

	out := cborItem(5, 5)
	out = append(out, cborItem(0, 1)...)
	out = append(out, cborItem(0, 2)...)
	out = append(out, cborItem(0, 3)...)
	out = append(out, cborItem(1, 6)...) // -7
	out = append(out, cborItem(1, 0)...) // -1
	out = append(out, cborItem(0, 1)...)
	out = append(out, cborItem(1, 1)...) // -2
	out = append(out, append(cborItem(2, 32), x...)...)
	out = append(out, cborItem(1, 2)...) // -3
	out = append(out, append(cborItem(2, 32), y...)...)
	return out
}

func (d *edgeDevice) authData(rpID string, flags byte, withCredential bool) []byte {
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

func (d *edgeDevice) attestation(rpID string) []byte {
	body := d.authData(rpID, 0x01|0x04|0x40, true)
	out := cborItem(5, 3)
	out = append(out, append(cborItem(3, 3), []byte("fmt")...)...)
	out = append(out, append(cborItem(3, 4), []byte("none")...)...)
	out = append(out, append(cborItem(3, 7), []byte("attStmt")...)...)
	out = append(out, cborItem(5, 0)...)
	out = append(out, append(cborItem(3, 8), []byte("authData")...)...)
	out = append(out, append(cborItem(2, uint64(len(body))), body...)...)
	return out
}

func edgeClientData(t *testing.T, dataType, challenge, origin string) []byte {
	t.Helper()

	encoded, err := json.Marshal(map[string]any{
		"type": dataType, "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

// TestPasskeyLifecycleThroughMachineEdge drives registration and a
// phishing-resistant login entirely over the protocol.
func TestPasskeyLifecycleThroughMachineEdge(t *testing.T) {
	t.Parallel()

	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	service.UseIssuer("https://id.example")
	processor := New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, err := service.Bootstrap(ctx, "acme", "test")
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	identifier := principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman, identifier, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	begun := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"pk-1","operation":"authenticator.passkey_register_begin","parameters":{"principal_id":"`+
			principal.ID+`"}}`,
	)[0]
	if !begun.OK {
		t.Fatalf("passkey_register_begin response = %#v", begun)
	}
	var registration identity.PasskeyRegistrationRequest
	if err := json.Unmarshal(mustMarshal(t, begun.Result), &registration); err != nil {
		t.Fatalf("decode registration request: %v", err)
	}
	if registration.RelyingPartyID != "id.example" || registration.Origin != "https://id.example" {
		t.Fatalf("registration request = %#v", registration)
	}

	device := newEdgeDevice(t)
	finish := func(id string, attestation, client []byte) Response {
		return runRequests(t, processor,
			`{"protocol_version":"1","request_id":"`+id+`","operation":"authenticator.passkey_register_finish","parameters":{"principal_id":"`+
				principal.ID+`","attestation_object":"`+base64.RawURLEncoding.EncodeToString(attestation)+
				`","client_data_json":"`+base64.RawURLEncoding.EncodeToString(client)+`"}}`,
		)[0]
	}

	// An attestation naming a different origin is refused: this is the
	// phishing case, arriving over the real protocol.
	phished := finish("pk-2", device.attestation(registration.RelyingPartyID),
		edgeClientData(t, "webauthn.create", registration.Challenge, "https://id.example.evil.test"))
	if phished.OK || phished.Error.Code != ErrorPasskeyRejected {
		t.Fatalf("a phished registration = %#v, want %s", phished, ErrorPasskeyRejected)
	}
	// That spent the challenge, so a genuine retry needs a fresh one.
	stale := finish("pk-3", device.attestation(registration.RelyingPartyID),
		edgeClientData(t, "webauthn.create", registration.Challenge, registration.Origin))
	if stale.OK || stale.Error.Code != ErrorPasskeyChallenge {
		t.Fatalf("a spent challenge = %#v, want %s", stale, ErrorPasskeyChallenge)
	}

	second := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"pk-4","operation":"authenticator.passkey_register_begin","parameters":{"principal_id":"`+
			principal.ID+`"}}`,
	)[0]
	if err := json.Unmarshal(mustMarshal(t, second.Result), &registration); err != nil {
		t.Fatalf("decode registration request: %v", err)
	}
	registered := finish("pk-5", device.attestation(registration.RelyingPartyID),
		edgeClientData(t, "webauthn.create", registration.Challenge, registration.Origin))
	if !registered.OK {
		t.Fatalf("passkey_register_finish response = %#v", registered)
	}
	var stored authenticatordomain.Passkey
	if err := json.Unmarshal(mustMarshal(t, registered.Result), &stored); err != nil {
		t.Fatalf("decode passkey: %v", err)
	}
	// The stored record carries a public key and a counter, nothing else.
	body := string(mustMarshal(t, registered.Result))
	if !strings.Contains(body, `"public_key"`) || strings.Contains(body, "private") {
		t.Fatalf("stored passkey = %s", body)
	}

	// Now log in with it, with no password anywhere in the flow.
	transaction, err := service.AuthenticationBegin(ctx, tenant.Tenant.ID, identifier, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	optionsResponse := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"pk-6","operation":"authn.passkey_options","parameters":{"transaction_id":"`+
			transaction.TransactionID+`"}}`,
	)[0]
	if !optionsResponse.OK {
		t.Fatalf("authn.passkey_options response = %#v", optionsResponse)
	}
	var options identity.PasskeyAuthenticationRequest
	if err := json.Unmarshal(mustMarshal(t, optionsResponse.Result), &options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	if len(options.CredentialIDs) != 1 || options.CredentialIDs[0] != stored.CredentialID {
		t.Fatalf("options = %#v", options)
	}

	device.signCount++
	assertionData := device.authData(options.RelyingPartyID, 0x01|0x04, false)
	assertionClient := edgeClientData(t, "webauthn.get", options.Challenge, options.Origin)
	clientHash := sha256.Sum256(assertionClient)
	digest := sha256.Sum256(append(append([]byte{}, assertionData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, device.key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}

	verified := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"pk-7","operation":"authn.verify_passkey","parameters":{"transaction_id":"`+
			transaction.TransactionID+`","credential_id":"`+stored.CredentialID+
			`","authenticator_data":"`+base64.RawURLEncoding.EncodeToString(assertionData)+
			`","client_data_json":"`+base64.RawURLEncoding.EncodeToString(assertionClient)+
			`","signature":"`+base64.RawURLEncoding.EncodeToString(signature)+`"}}`,
	)[0]
	if !verified.OK {
		t.Fatalf("authn.verify_passkey response = %#v", verified)
	}
	var result identity.AuthenticationResult
	if err := json.Unmarshal(mustMarshal(t, verified.Result), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	// A user-verified passkey is two factors in one gesture.
	if result.Assurance != "mfa" {
		t.Fatalf("assurance = %q, want mfa", result.Assurance)
	}

	listed := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"pk-8","operation":"authenticator.passkey_list","parameters":{"principal_id":"`+
			principal.ID+`"}}`,
		`{"protocol_version":"1","request_id":"pk-9","operation":"authenticator.passkey_remove","parameters":{"credential_id":"`+
			stored.CredentialID+`"}}`,
		`{"protocol_version":"1","request_id":"pk-10","operation":"authenticator.passkey_remove","parameters":{"credential_id":"`+
			stored.CredentialID+`"}}`,
	)
	if !listed[0].OK || !strings.Contains(string(mustMarshal(t, listed[0].Result)), stored.CredentialID) {
		t.Fatalf("authenticator.passkey_list = %#v", listed[0])
	}
	if !listed[1].OK {
		t.Fatalf("authenticator.passkey_remove = %#v", listed[1])
	}
	if listed[2].OK || listed[2].Error.Code != ErrorPasskeyNotFound {
		t.Fatalf("removing twice = %#v, want %s", listed[2], ErrorPasskeyNotFound)
	}
}

func TestPasskeyFailsClosedWithoutAnIssuerAtTheEdge(t *testing.T) {
	t.Parallel()

	service, err := identity.New(&memoryLedger{}, nil)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	processor := New(system.New(buildinfo.New("", "", "")), service)

	ctx := context.Background()
	tenant, _ := service.Bootstrap(ctx, "acme", "test")
	principal, err := service.PrincipalCreate(ctx, tenant.Tenant.ID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}

	// A passkey is bound to a domain. Without an issuer there is nothing to
	// bind it to, so the engine refuses rather than guessing one.
	response := runRequests(t, processor,
		`{"protocol_version":"1","request_id":"pk-0","operation":"authenticator.passkey_register_begin","parameters":{"principal_id":"`+
			principal.ID+`"}}`,
	)[0]
	if response.OK || response.Error.Code != ErrorRelyingPartyMissing {
		t.Fatalf("response = %#v, want %s", response, ErrorRelyingPartyMissing)
	}
}
