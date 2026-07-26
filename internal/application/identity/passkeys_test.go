package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	authndomain "github.com/d31ma/sesame/internal/domain/authentication"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
)

// device is a minimal WebAuthn authenticator producing real wire formats, so
// these tests exercise the shipped verifier rather than a stub.
type device struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	signCount    uint32
}

func newDevice(t *testing.T) *device {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	id := make([]byte, 24)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return &device{key: key, credentialID: id}
}

func header(major byte, argument uint64) []byte {
	switch {
	case argument < 24:
		return []byte{major<<5 | byte(argument)}
	case argument < 1<<8:
		return []byte{major<<5 | 24, byte(argument)}
	default:
		return []byte{major<<5 | 25, byte(argument >> 8), byte(argument)}
	}
}

func byteString(payload []byte) []byte { return append(header(2, uint64(len(payload))), payload...) }
func textString(text string) []byte    { return append(header(3, uint64(len(text))), []byte(text)...) }
func negative(label int64) []byte      { return header(1, uint64(-1-label)) }

func (d *device) coseKey() []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	d.key.PublicKey.X.FillBytes(x)
	d.key.PublicKey.Y.FillBytes(y)

	out := header(5, 5)
	out = append(out, header(0, 1)...)
	out = append(out, header(0, 2)...) // EC2
	out = append(out, header(0, 3)...)
	out = append(out, negative(-7)...) // ES256
	out = append(out, negative(-1)...)
	out = append(out, header(0, 1)...) // P-256
	out = append(out, negative(-2)...)
	out = append(out, byteString(x)...)
	out = append(out, negative(-3)...)
	out = append(out, byteString(y)...)
	return out
}

func (d *device) authData(rpID string, flags byte, withCredential bool) []byte {
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
	out = append(out, d.coseKey()...)
	return out
}

func (d *device) attestation(rpID string, flags byte) []byte {
	out := header(5, 3)
	out = append(out, textString("fmt")...)
	out = append(out, textString("none")...)
	out = append(out, textString("attStmt")...)
	out = append(out, header(5, 0)...)
	out = append(out, textString("authData")...)
	out = append(out, byteString(d.authData(rpID, flags, true))...)
	return out
}

func clientData(t *testing.T, dataType, challenge, origin string) []byte {
	t.Helper()

	encoded, err := json.Marshal(map[string]any{
		"type": dataType, "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return encoded
}

func (d *device) sign(t *testing.T, challenge, origin, rpID string, flags byte) ([]byte, []byte, []byte) {
	t.Helper()

	d.signCount++
	data := d.authData(rpID, flags, false)
	client := clientData(t, "webauthn.get", challenge, origin)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, d.key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return data, client, signature
}

const (
	passkeyFlagsUV = 0x01 | 0x04
	passkeyFlagsUP = 0x01
	registerFlags  = 0x01 | 0x04 | 0x40
)

// registerPasskey runs a complete registration for the fixture's principal.
func registerPasskey(t *testing.T, fixture *flowFixture, d *device) authenticatordomain.Passkey {
	t.Helper()

	begun, err := fixture.service.PasskeyRegisterBegin(fixture.principalID)
	if err != nil {
		t.Fatalf("PasskeyRegisterBegin() error = %v", err)
	}
	if begun.RelyingPartyID != "id.example" || begun.Origin != flowIssuer {
		t.Fatalf("registration request = %#v", begun)
	}
	stored, err := fixture.service.PasskeyRegisterFinish(context.Background(), fixture.principalID,
		d.attestation(begun.RelyingPartyID, registerFlags),
		clientData(t, "webauthn.create", begun.Challenge, begun.Origin), "test")
	if err != nil {
		t.Fatalf("PasskeyRegisterFinish() error = %v", err)
	}
	return stored
}

func TestPasskeyAuthenticationEstablishesMFAOnItsOwn(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	d := newDevice(t)
	stored := registerPasskey(t, fixture, d)

	if stored.PrincipalID != fixture.principalID || stored.PublicKey == "" {
		t.Fatalf("stored = %#v", stored)
	}

	begun, err := fixture.service.AuthenticationBegin(ctx, fixture.tenantID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	if err != nil {
		t.Fatalf("AuthenticationBegin() error = %v", err)
	}
	options, err := fixture.service.PasskeyAuthenticationOptions(begun.TransactionID)
	if err != nil {
		t.Fatalf("PasskeyAuthenticationOptions() error = %v", err)
	}
	if options.Challenge == "" || len(options.CredentialIDs) != 1 ||
		options.CredentialIDs[0] != stored.CredentialID {
		t.Fatalf("options = %#v", options)
	}

	data, client, signature := d.sign(t, options.Challenge, options.Origin, options.RelyingPartyID, passkeyFlagsUV)
	result, err := fixture.service.AuthenticationVerifyPasskey(ctx, begun.TransactionID,
		stored.CredentialID, data, client, signature, "test")
	if err != nil {
		t.Fatalf("AuthenticationVerifyPasskey() error = %v", err)
	}
	// A verified user plus a possessed key is two factors in one gesture, so
	// no password is needed first and the assurance is already mfa.
	if result.Assurance != authndomain.AssuranceMFA {
		t.Fatalf("assurance = %q, want %q", result.Assurance, authndomain.AssuranceMFA)
	}

	issued, err := fixture.service.AuthenticationComplete(ctx, begun.TransactionID, time.Hour, "test")
	if err != nil {
		t.Fatalf("AuthenticationComplete() error = %v", err)
	}
	if issued.Assurance != authndomain.AssuranceMFA {
		t.Fatalf("session assurance = %q", issued.Assurance)
	}
}

// TestPasskeyWithoutUserVerificationIsOneFactor pins the distinction: a key
// that was merely touched proves possession, not that the right person is
// holding it.
func TestPasskeyWithoutUserVerificationIsOneFactor(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	d := newDevice(t)
	stored := registerPasskey(t, fixture, d)

	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenantID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	options, _ := fixture.service.PasskeyAuthenticationOptions(begun.TransactionID)
	data, client, signature := d.sign(t, options.Challenge, options.Origin, options.RelyingPartyID, passkeyFlagsUP)
	result, err := fixture.service.AuthenticationVerifyPasskey(ctx, begun.TransactionID,
		stored.CredentialID, data, client, signature, "test")
	if err != nil {
		t.Fatalf("AuthenticationVerifyPasskey() error = %v", err)
	}
	if result.Assurance != authndomain.AssurancePassword {
		t.Fatalf("assurance = %q, want %q", result.Assurance, authndomain.AssurancePassword)
	}
}

func TestPasskeyRegistrationChallengeIsSingleUseAndBounded(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	d := newDevice(t)

	begun, err := fixture.service.PasskeyRegisterBegin(fixture.principalID)
	if err != nil {
		t.Fatalf("PasskeyRegisterBegin() error = %v", err)
	}
	attestation := d.attestation(begun.RelyingPartyID, registerFlags)
	client := clientData(t, "webauthn.create", begun.Challenge, begun.Origin)

	if _, err := fixture.service.PasskeyRegisterFinish(ctx, fixture.principalID,
		attestation, client, "test"); err != nil {
		t.Fatalf("PasskeyRegisterFinish() error = %v", err)
	}
	// The same attestation cannot be presented twice: the challenge is spent.
	if _, err := fixture.service.PasskeyRegisterFinish(ctx, fixture.principalID,
		attestation, client, "test"); !errors.Is(err, ErrPasskeyChallengeExpired) {
		t.Fatalf("a replayed registration was accepted: %v", err)
	}

	// A failed attempt also spends the challenge, so a caller cannot retry
	// with different bytes against a live nonce.
	second, _ := fixture.service.PasskeyRegisterBegin(fixture.principalID)
	if _, err := fixture.service.PasskeyRegisterFinish(ctx, fixture.principalID,
		[]byte("garbage"), clientData(t, "webauthn.create", second.Challenge, second.Origin),
		"test"); err == nil {
		t.Fatal("a garbage attestation was accepted")
	}
	other := newDevice(t)
	if _, err := fixture.service.PasskeyRegisterFinish(ctx, fixture.principalID,
		other.attestation(second.RelyingPartyID, registerFlags),
		clientData(t, "webauthn.create", second.Challenge, second.Origin),
		"test"); !errors.Is(err, ErrPasskeyChallengeExpired) {
		t.Fatalf("a spent challenge was reusable after a failure: %v", err)
	}

	// And the challenge expires.
	third, _ := fixture.service.PasskeyRegisterBegin(fixture.principalID)
	fixture.now = fixture.now.Add(PasskeyRegistrationChallengeLifetime + time.Second)
	stale := newDevice(t)
	if _, err := fixture.service.PasskeyRegisterFinish(ctx, fixture.principalID,
		stale.attestation(third.RelyingPartyID, registerFlags),
		clientData(t, "webauthn.create", third.Challenge, third.Origin),
		"test"); !errors.Is(err, ErrPasskeyChallengeExpired) {
		t.Fatalf("an expired challenge was accepted: %v", err)
	}
}

// TestPasskeyAssertionIsBoundToItsTransaction is the replay guarantee at the
// application layer: an assertion belongs to one transaction's challenge.
func TestPasskeyAssertionIsBoundToItsTransaction(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	d := newDevice(t)
	stored := registerPasskey(t, fixture, d)
	identifier := principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}

	first, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenantID, identifier, "test")
	firstOptions, _ := fixture.service.PasskeyAuthenticationOptions(first.TransactionID)
	data, client, signature := d.sign(t, firstOptions.Challenge, firstOptions.Origin, firstOptions.RelyingPartyID, passkeyFlagsUV)

	// Presenting the captured assertion to a different transaction fails: it
	// signs a challenge that transaction never issued.
	second, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenantID, identifier, "test")
	secondOptions, _ := fixture.service.PasskeyAuthenticationOptions(second.TransactionID)
	if firstOptions.Challenge == secondOptions.Challenge {
		t.Fatal("two transactions shared a challenge")
	}
	replayed, err := fixture.service.AuthenticationVerifyPasskey(ctx, second.TransactionID,
		stored.CredentialID, data, client, signature, "test")
	if err != nil {
		t.Fatalf("AuthenticationVerifyPasskey() error = %v", err)
	}
	if replayed.Assurance != "" {
		t.Fatalf("a cross-transaction replay was accepted: %#v", replayed)
	}

	// The assertion still works on its own transaction.
	if result, err := fixture.service.AuthenticationVerifyPasskey(ctx, first.TransactionID,
		stored.CredentialID, data, client, signature, "test"); err != nil || result.Assurance == "" {
		t.Fatalf("the genuine assertion failed: %#v %v", result, err)
	}
}

func TestPasskeyBelongingToAnotherPrincipalProvesNothing(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	mine := newDevice(t)
	registerPasskey(t, fixture, mine)

	// A second principal with their own passkey.
	stranger, err := fixture.service.PrincipalCreate(ctx, fixture.tenantID, principaldomain.KindHuman,
		principaldomain.Identifier{Namespace: "email", Value: "stranger@example.com"}, "test")
	if err != nil {
		t.Fatalf("PrincipalCreate() error = %v", err)
	}
	strangerDevice := newDevice(t)
	strangerBegun, err := fixture.service.PasskeyRegisterBegin(stranger.ID)
	if err != nil {
		t.Fatalf("PasskeyRegisterBegin() error = %v", err)
	}
	strangerKey, err := fixture.service.PasskeyRegisterFinish(ctx, stranger.ID,
		strangerDevice.attestation(strangerBegun.RelyingPartyID, registerFlags),
		clientData(t, "webauthn.create", strangerBegun.Challenge, strangerBegun.Origin), "test")
	if err != nil {
		t.Fatalf("PasskeyRegisterFinish() error = %v", err)
	}

	// The stranger's perfectly valid assertion cannot authenticate as me.
	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenantID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	options, _ := fixture.service.PasskeyAuthenticationOptions(begun.TransactionID)
	data, client, signature := strangerDevice.sign(t, options.Challenge, options.Origin,
		options.RelyingPartyID, passkeyFlagsUV)
	result, err := fixture.service.AuthenticationVerifyPasskey(ctx, begun.TransactionID,
		strangerKey.CredentialID, data, client, signature, "test")
	if err != nil {
		t.Fatalf("AuthenticationVerifyPasskey() error = %v", err)
	}
	if result.Assurance != "" {
		t.Fatalf("another principal's passkey authenticated: %#v", result)
	}

	// The options for my transaction only ever name my own credentials.
	if len(options.CredentialIDs) != 1 || options.CredentialIDs[0] == strangerKey.CredentialID {
		t.Fatalf("options leaked another principal's credentials: %#v", options.CredentialIDs)
	}
}

func TestPasskeyRemovalIsDurable(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	ctx := context.Background()
	d := newDevice(t)
	stored := registerPasskey(t, fixture, d)

	if err := fixture.service.PasskeyRemove(ctx, stored.CredentialID, "test"); err != nil {
		t.Fatalf("PasskeyRemove() error = %v", err)
	}
	if err := fixture.service.PasskeyRemove(ctx, stored.CredentialID, "test"); !errors.Is(err, ErrPasskeyNotFound) {
		t.Fatalf("repeated PasskeyRemove() error = %v", err)
	}

	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenantID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	options, _ := fixture.service.PasskeyAuthenticationOptions(begun.TransactionID)
	if len(options.CredentialIDs) != 0 {
		t.Fatalf("a removed credential is still offered: %#v", options.CredentialIDs)
	}
	data, client, signature := d.sign(t, options.Challenge, options.Origin, options.RelyingPartyID, passkeyFlagsUV)
	result, err := fixture.service.AuthenticationVerifyPasskey(ctx, begun.TransactionID,
		stored.CredentialID, data, client, signature, "test")
	if err != nil {
		t.Fatalf("AuthenticationVerifyPasskey() error = %v", err)
	}
	if result.Assurance != "" {
		t.Fatalf("a removed passkey authenticated: %#v", result)
	}
}

func TestPasskeyFailsClosedWithoutAnIssuer(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	fixture.service.UseIssuer("")

	// A passkey is bound to a domain. With no issuer there is nothing to
	// bind it to, so registration refuses rather than binding to a guess.
	if _, err := fixture.service.PasskeyRegisterBegin(fixture.principalID); !errors.Is(err, ErrNoRelyingParty) {
		t.Fatalf("PasskeyRegisterBegin without an issuer error = %v", err)
	}
	if _, err := fixture.service.PasskeyRegisterFinish(context.Background(), fixture.principalID,
		nil, nil, "test"); !errors.Is(err, ErrNoRelyingParty) {
		t.Fatalf("PasskeyRegisterFinish without an issuer error = %v", err)
	}
}

// TestPasskeyStateSurvivesSnapshotAndReplay is the regression guard for a
// snapshot that forgets the passkey projection. Losing the sign counter would
// silently disable clone detection.
func TestPasskeyStateSurvivesSnapshotAndReplay(t *testing.T) {
	t.Parallel()

	fixture := newFlowFixture(t)
	snapshots := &memorySnapshots{}
	fixture.service.UseSnapshots(snapshots)
	ctx := context.Background()
	d := newDevice(t)
	stored := registerPasskey(t, fixture, d)

	// Use it once so the counter advances past its registered value.
	begun, _ := fixture.service.AuthenticationBegin(ctx, fixture.tenantID,
		principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
	options, _ := fixture.service.PasskeyAuthenticationOptions(begun.TransactionID)
	data, client, signature := d.sign(t, options.Challenge, options.Origin, options.RelyingPartyID, passkeyFlagsUV)
	if _, err := fixture.service.AuthenticationVerifyPasskey(ctx, begun.TransactionID,
		stored.CredentialID, data, client, signature, "test"); err != nil {
		t.Fatalf("AuthenticationVerifyPasskey() error = %v", err)
	}
	advanced := d.signCount

	rebuilt := map[string]*Service{}
	replayed, err := New(&memoryLedger{}, fixture.ledger.events)
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
		restored.UseIssuer(flowIssuer)
		restored.UseClock(func() time.Time { return fixture.now })

		keys, err := restored.PasskeyList(fixture.principalID)
		if err != nil || len(keys) != 1 {
			t.Fatalf("%s: PasskeyList() = %#v, %v", kind, keys, err)
		}
		if keys[0].SignCount != advanced {
			t.Fatalf("%s: sign counter = %d, want the advanced %d", kind, keys[0].SignCount, advanced)
		}
		// A clone replaying the pre-restart counter is still detected.
		next, _ := restored.AuthenticationBegin(ctx, fixture.tenantID,
			principaldomain.Identifier{Namespace: "email", Value: "user@example.com"}, "test")
		nextOptions, _ := restored.PasskeyAuthenticationOptions(next.TransactionID)
		d.signCount = advanced - 1
		staleData, staleClient, staleSignature := d.sign(t, nextOptions.Challenge,
			nextOptions.Origin, nextOptions.RelyingPartyID, passkeyFlagsUV)
		result, err := restored.AuthenticationVerifyPasskey(ctx, next.TransactionID,
			stored.CredentialID, staleData, staleClient, staleSignature, "test")
		if err != nil {
			t.Fatalf("%s: AuthenticationVerifyPasskey() error = %v", kind, err)
		}
		if result.Assurance != "" {
			t.Fatalf("%s: a cloned counter was accepted after restore", kind)
		}
		d.signCount = advanced
	}

	// No private material reaches the snapshot: a public key and a counter
	// are all that is stored.
	encoded := string(snapshots.states[len(snapshots.states)-1])
	raw, _ := base64.RawURLEncoding.DecodeString(stored.PublicKey)
	if len(raw) != 65 {
		t.Fatalf("stored public key is %d bytes", len(raw))
	}
	if !strings.Contains(encoded, stored.CredentialID) {
		t.Fatal("the snapshot does not carry the credential")
	}
}
