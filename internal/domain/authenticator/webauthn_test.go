package authenticator

import (
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
)

const (
	testOrigin = "https://id.example"
	testRPID   = "id.example"
)

// fakeAuthenticator is a minimal but faithful WebAuthn authenticator: it
// produces the same byte layouts a real one does, so the verifier under test
// is exercised against the real wire format rather than a convenient stub.
type fakeAuthenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	signCount    uint32
}

func newFakeAuthenticator(t *testing.T) *fakeAuthenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return &fakeAuthenticator{key: key, credentialID: id}
}

// cborBytes encodes a byte string header plus payload.
func cborByteString(payload []byte) []byte {
	return append(cborHeader(2, uint64(len(payload))), payload...)
}

func cborTextString(text string) []byte {
	return append(cborHeader(3, uint64(len(text))), []byte(text)...)
}

func cborHeader(major byte, argument uint64) []byte {
	switch {
	case argument < 24:
		return []byte{major<<5 | byte(argument)}
	case argument < 1<<8:
		return []byte{major<<5 | 24, byte(argument)}
	case argument < 1<<16:
		return []byte{major<<5 | 25, byte(argument >> 8), byte(argument)}
	default:
		return []byte{major<<5 | 26,
			byte(argument >> 24), byte(argument >> 16), byte(argument >> 8), byte(argument)}
	}
}

func cborNegativeLabel(label int64) []byte {
	return cborHeader(1, uint64(-1-label))
}

// coseKey encodes the ES256 public key exactly as an authenticator would.
func (a *fakeAuthenticator) coseKey() []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	a.key.PublicKey.X.FillBytes(x)
	a.key.PublicKey.Y.FillBytes(y)

	out := cborHeader(5, 5) // five-entry map
	out = append(out, cborHeader(0, 1)...)
	out = append(out, cborHeader(0, coseKeyTypeEC2)...)
	out = append(out, cborHeader(0, 3)...)
	out = append(out, cborNegativeLabel(coseAlgorithmES256)...)
	out = append(out, cborNegativeLabel(-1)...)
	out = append(out, cborHeader(0, coseCurveP256)...)
	out = append(out, cborNegativeLabel(-2)...)
	out = append(out, cborByteString(x)...)
	out = append(out, cborNegativeLabel(-3)...)
	out = append(out, cborByteString(y)...)
	return out
}

func (a *fakeAuthenticator) authData(rpID string, flags byte, includeCredential bool) []byte {
	hash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, hash[:]...)
	out = append(out, flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, a.signCount)
	out = append(out, counter...)
	if !includeCredential {
		return out
	}
	out = append(out, make([]byte, 16)...) // AAGUID
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(a.credentialID)))
	out = append(out, length...)
	out = append(out, a.credentialID...)
	out = append(out, a.coseKey()...)
	return out
}

func (a *fakeAuthenticator) attestationObject(format, rpID string, flags byte) []byte {
	out := cborHeader(5, 3)
	out = append(out, cborTextString("fmt")...)
	out = append(out, cborTextString(format)...)
	out = append(out, cborTextString("attStmt")...)
	out = append(out, cborHeader(5, 0)...) // empty map
	out = append(out, cborTextString("authData")...)
	out = append(out, cborByteString(a.authData(rpID, flags, true))...)
	return out
}

func browserClientData(t *testing.T, dataType, challenge, origin string, crossOrigin bool) []byte {
	t.Helper()

	encoded, err := json.Marshal(map[string]any{
		"type":        dataType,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": crossOrigin,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return encoded
}

// assert produces a signed assertion, advancing the counter the way a real
// authenticator does.
func (a *fakeAuthenticator) assert(t *testing.T, challenge, origin, rpID string, flags byte) ([]byte, []byte, []byte) {
	t.Helper()

	a.signCount++
	data := a.authData(rpID, flags, false)
	client := browserClientData(t, clientDataTypeGet, challenge, origin, false)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return data, client, signature
}

func registerFake(t *testing.T, device *fakeAuthenticator, challenge string) Passkey {
	t.Helper()

	registered, err := VerifyPasskeyRegistration(
		device.attestationObject(AttestationNone, testRPID, flagUserPresent|flagUserVerified|flagAttestedCredData),
		browserClientData(t, clientDataTypeCreate, challenge, testOrigin, false),
		challenge, testOrigin, testRPID,
	)
	if err != nil {
		t.Fatalf("VerifyPasskeyRegistration() error = %v", err)
	}
	return Passkey{
		CredentialID: registered.CredentialID,
		PublicKey:    registered.PublicKey,
		SignCount:    registered.SignCount,
		UserVerified: registered.UserVerified,
	}
}

func TestPasskeyRegistrationAndAssertionRoundTrip(t *testing.T) {
	t.Parallel()

	device := newFakeAuthenticator(t)
	challenge, err := NewPasskeyChallenge()
	if err != nil {
		t.Fatalf("NewPasskeyChallenge() error = %v", err)
	}
	stored := registerFake(t, device, challenge)

	if stored.CredentialID != base64.RawURLEncoding.EncodeToString(device.credentialID) {
		t.Fatalf("credential ID = %q", stored.CredentialID)
	}
	if !stored.UserVerified {
		t.Fatal("the user-verified flag did not survive registration")
	}
	if err := ValidateCredentialID(stored.CredentialID); err != nil {
		t.Fatalf("ValidateCredentialID() = %v", err)
	}

	assertionChallenge, _ := NewPasskeyChallenge()
	data, client, signature := device.assert(t, assertionChallenge, testOrigin, testRPID,
		flagUserPresent|flagUserVerified)
	asserted, err := VerifyPasskeyAssertion(stored, data, client, signature,
		assertionChallenge, testOrigin, testRPID)
	if err != nil {
		t.Fatalf("VerifyPasskeyAssertion() error = %v", err)
	}
	if !asserted.UserVerified || asserted.SignCount != device.signCount {
		t.Fatalf("asserted = %#v", asserted)
	}
}

// TestPasskeyAssertionIsPhishingResistant is the property that makes a
// passkey worth more than a password: an assertion collected by a replica of
// the login page names the replica's origin and is refused here, even though
// the signature itself is perfectly valid.
func TestPasskeyAssertionIsPhishingResistant(t *testing.T) {
	t.Parallel()

	device := newFakeAuthenticator(t)
	challenge, _ := NewPasskeyChallenge()
	stored := registerFake(t, device, challenge)

	assertionChallenge, _ := NewPasskeyChallenge()

	// The browser talked to an attacker, so it signs the attacker's origin.
	data, client, signature := device.assert(t, assertionChallenge,
		"https://id.example.evil.test", testRPID, flagUserPresent)
	if _, err := VerifyPasskeyAssertion(stored, data, client, signature,
		assertionChallenge, testOrigin, testRPID); !errors.Is(err, ErrPasskeyInvalidClientData) {
		t.Fatalf("a phished assertion was accepted: %v", err)
	}

	// An authenticator scoped to another relying party cannot answer either.
	data, client, signature = device.assert(t, assertionChallenge, testOrigin, "evil.test", flagUserPresent)
	if _, err := VerifyPasskeyAssertion(stored, data, client, signature,
		assertionChallenge, testOrigin, testRPID); !errors.Is(err, ErrPasskeyInvalidAuthData) {
		t.Fatalf("a wrong relying party ID was accepted: %v", err)
	}

	// A credential used from inside a cross-origin frame is refused.
	device.signCount++
	crossData := device.authData(testRPID, flagUserPresent, false)
	crossClient := browserClientData(t, clientDataTypeGet, assertionChallenge, testOrigin, true)
	crossHash := sha256.Sum256(crossClient)
	crossDigest := sha256.Sum256(append(append([]byte{}, crossData...), crossHash[:]...))
	crossSignature, _ := ecdsa.SignASN1(rand.Reader, device.key, crossDigest[:])
	if _, err := VerifyPasskeyAssertion(stored, crossData, crossClient, crossSignature,
		assertionChallenge, testOrigin, testRPID); !errors.Is(err, ErrPasskeyInvalidClientData) {
		t.Fatalf("a cross-origin assertion was accepted: %v", err)
	}
}

func TestPasskeyAssertionRefusesReplayAndTampering(t *testing.T) {
	t.Parallel()

	device := newFakeAuthenticator(t)
	challenge, _ := NewPasskeyChallenge()
	stored := registerFake(t, device, challenge)

	assertionChallenge, _ := NewPasskeyChallenge()
	data, client, signature := device.assert(t, assertionChallenge, testOrigin, testRPID, flagUserPresent)

	// A different challenge than the one the engine issued.
	other, _ := NewPasskeyChallenge()
	if _, err := VerifyPasskeyAssertion(stored, data, client, signature,
		other, testOrigin, testRPID); !errors.Is(err, ErrPasskeyInvalidClientData) {
		t.Fatalf("a replayed challenge was accepted: %v", err)
	}

	// A registration assertion presented as an authentication one.
	wrongType := browserClientData(t, clientDataTypeCreate, assertionChallenge, testOrigin, false)
	if _, err := VerifyPasskeyAssertion(stored, data, wrongType, signature,
		assertionChallenge, testOrigin, testRPID); !errors.Is(err, ErrPasskeyInvalidClientData) {
		t.Fatalf("a webauthn.create assertion was accepted for a get: %v", err)
	}

	// A signature from a different key.
	stranger := newFakeAuthenticator(t)
	strangerStored := stored
	strangerKey := registerFake(t, stranger, challenge)
	strangerStored.PublicKey = strangerKey.PublicKey
	if _, err := VerifyPasskeyAssertion(strangerStored, data, client, signature,
		assertionChallenge, testOrigin, testRPID); !errors.Is(err, ErrPasskeyInvalidSignature) {
		t.Fatalf("a signature from another key was accepted: %v", err)
	}

	// Flipping a flag byte invalidates the signature, because the signature
	// covers the authenticator data itself.
	tampered := append([]byte{}, data...)
	tampered[32] |= flagUserVerified
	if _, err := VerifyPasskeyAssertion(stored, tampered, client, signature,
		assertionChallenge, testOrigin, testRPID); !errors.Is(err, ErrPasskeyInvalidSignature) {
		t.Fatalf("a tampered user-verified flag was accepted: %v", err)
	}

	// User presence is mandatory: without it, nobody touched the device.
	device.signCount++
	absent := device.authData(testRPID, 0, false)
	absentClient := browserClientData(t, clientDataTypeGet, assertionChallenge, testOrigin, false)
	absentHash := sha256.Sum256(absentClient)
	absentDigest := sha256.Sum256(append(append([]byte{}, absent...), absentHash[:]...))
	absentSignature, _ := ecdsa.SignASN1(rand.Reader, device.key, absentDigest[:])
	if _, err := VerifyPasskeyAssertion(stored, absent, absentClient, absentSignature,
		assertionChallenge, testOrigin, testRPID); !errors.Is(err, ErrPasskeyInvalidAuthData) {
		t.Fatalf("an assertion without user presence was accepted: %v", err)
	}
}

// TestPasskeyCloneDetection covers the one signal WebAuthn gives that a
// credential has been copied out of its authenticator.
func TestPasskeyCloneDetection(t *testing.T) {
	t.Parallel()

	device := newFakeAuthenticator(t)
	challenge, _ := NewPasskeyChallenge()
	stored := registerFake(t, device, challenge)

	assertionChallenge, _ := NewPasskeyChallenge()
	data, client, signature := device.assert(t, assertionChallenge, testOrigin, testRPID, flagUserPresent)
	asserted, err := VerifyPasskeyAssertion(stored, data, client, signature,
		assertionChallenge, testOrigin, testRPID)
	if err != nil {
		t.Fatalf("VerifyPasskeyAssertion() error = %v", err)
	}
	stored.SignCount = asserted.SignCount

	// A clone replays an older counter.
	device.signCount = asserted.SignCount - 1
	replayChallenge, _ := NewPasskeyChallenge()
	staleData, staleClient, staleSignature := device.assert(t, replayChallenge, testOrigin, testRPID, flagUserPresent)
	if _, err := VerifyPasskeyAssertion(stored, staleData, staleClient, staleSignature,
		replayChallenge, testOrigin, testRPID); !errors.Is(err, ErrPasskeyCloned) {
		t.Fatalf("a stale sign counter was accepted: %v", err)
	}

	// An authenticator that reports a constant zero is the documented
	// "counter not supported" case, not a clone.
	zeroDevice := newFakeAuthenticator(t)
	zeroChallenge, _ := NewPasskeyChallenge()
	zeroStored := registerFake(t, zeroDevice, zeroChallenge)
	zeroStored.SignCount = 0
	zeroDevice.signCount = 0
	zeroData := zeroDevice.authData(testRPID, flagUserPresent, false)
	zeroClient := browserClientData(t, clientDataTypeGet, zeroChallenge, testOrigin, false)
	zeroHash := sha256.Sum256(zeroClient)
	zeroDigest := sha256.Sum256(append(append([]byte{}, zeroData...), zeroHash[:]...))
	zeroSignature, _ := ecdsa.SignASN1(rand.Reader, zeroDevice.key, zeroDigest[:])
	if _, err := VerifyPasskeyAssertion(zeroStored, zeroData, zeroClient, zeroSignature,
		zeroChallenge, testOrigin, testRPID); err != nil {
		t.Fatalf("a zero-counter authenticator was treated as cloned: %v", err)
	}
}

func TestPasskeyRegistrationRefusesUnsupportedShapes(t *testing.T) {
	t.Parallel()

	device := newFakeAuthenticator(t)
	challenge, _ := NewPasskeyChallenge()
	client := browserClientData(t, clientDataTypeCreate, challenge, testOrigin, false)
	flags := byte(flagUserPresent | flagAttestedCredData)

	// An unverified attestation statement is refused rather than accepted as
	// if it said nothing.
	for _, format := range []string{"packed", "tpm", "android-key", "apple", "fido-u2f"} {
		if _, err := VerifyPasskeyRegistration(
			device.attestationObject(format, testRPID, flags), client,
			challenge, testOrigin, testRPID,
		); !errors.Is(err, ErrPasskeyUnsupportedAttestation) {
			t.Fatalf("attestation format %q was accepted: %v", format, err)
		}
	}

	// A registration without the attested-credential-data flag carries no key.
	if _, err := VerifyPasskeyRegistration(
		device.attestationObject(AttestationNone, testRPID, flagUserPresent), client,
		challenge, testOrigin, testRPID,
	); !errors.Is(err, ErrPasskeyInvalidAuthData) {
		t.Fatalf("a registration with no credential data was accepted: %v", err)
	}

	// Wrong origin, wrong challenge, wrong RP ID.
	if _, err := VerifyPasskeyRegistration(
		device.attestationObject(AttestationNone, testRPID, flags), client,
		challenge, "https://evil.test", testRPID,
	); !errors.Is(err, ErrPasskeyInvalidClientData) {
		t.Fatalf("a wrong origin was accepted: %v", err)
	}
	if _, err := VerifyPasskeyRegistration(
		device.attestationObject(AttestationNone, "evil.test", flags), client,
		challenge, testOrigin, testRPID,
	); !errors.Is(err, ErrPasskeyInvalidAuthData) {
		t.Fatalf("a wrong relying party ID was accepted: %v", err)
	}

	// Garbage input never panics and never passes.
	for name, attestation := range map[string][]byte{
		"empty":     {},
		"not cbor":  []byte("hello"),
		"truncated": device.attestationObject(AttestationNone, testRPID, flags)[:5],
	} {
		if _, err := VerifyPasskeyRegistration(attestation, client, challenge, testOrigin, testRPID); err == nil {
			t.Fatalf("a %s attestation object was accepted", name)
		}
	}
}

func TestRelyingPartyIDDerivesFromIssuer(t *testing.T) {
	t.Parallel()

	id, err := RelyingPartyID("https://id.example/auth")
	if err != nil || id != "id.example" {
		t.Fatalf("RelyingPartyID() = %q, %v", id, err)
	}
	if _, err := RelyingPartyID("not a url"); err == nil {
		t.Fatal("RelyingPartyID accepted a malformed issuer")
	}
}

func TestValidateCredentialID(t *testing.T) {
	t.Parallel()

	valid := base64.RawURLEncoding.EncodeToString([]byte("credential"))
	if err := ValidateCredentialID(valid); err != nil {
		t.Fatalf("ValidateCredentialID(%q) = %v", valid, err)
	}
	oversized := base64.RawURLEncoding.EncodeToString(make([]byte, maxCredentialIDLength+1))
	for _, bad := range []string{"", "not base64!", oversized} {
		if err := ValidateCredentialID(bad); err == nil {
			t.Fatalf("ValidateCredentialID accepted %q", bad)
		}
	}
}

func TestChallengesAreFreshAndUnpredictable(t *testing.T) {
	t.Parallel()

	seen := map[string]struct{}{}
	for index := 0; index < 64; index++ {
		challenge, err := NewPasskeyChallenge()
		if err != nil {
			t.Fatalf("NewPasskeyChallenge() error = %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(challenge)
		if err != nil || len(raw) != challengeBytes {
			t.Fatalf("challenge %q decodes to %d bytes", challenge, len(raw))
		}
		if _, duplicate := seen[challenge]; duplicate {
			t.Fatal("NewPasskeyChallenge repeated a value")
		}
		seen[challenge] = struct{}{}
	}
}

func TestCBORReaderRefusesHostileInput(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"indefinite length map":   {0xbf, 0xff},
		"indefinite length bytes": {0x5f, 0xff},
		"tag":                     {0xc0, 0x01},
		"float":                   {0xfb, 0, 0, 0, 0, 0, 0, 0, 0},
		"length beyond input":     {0x5a, 0xff, 0xff, 0xff, 0xff, 0x01},
		"truncated argument":      {0x5a, 0x00},
		"too many map items":      append(cborHeader(5, maxCBORItems+1), 0x01, 0x01),
		"empty":                   {},
	}
	for name, input := range cases {
		if _, _, err := decodeCBOR(input); err == nil {
			t.Fatalf("decodeCBOR accepted %s", name)
		}
	}

	// A duplicate key would let one value be shown to two readers.
	duplicate := append(cborHeader(5, 2), 0x01, 0x01, 0x01, 0x02)
	if _, _, err := decodeCBOR(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("decodeCBOR accepted a duplicate map key: %v", err)
	}

	// Deep nesting terminates rather than exhausting the stack.
	deep := []byte{}
	for index := 0; index < maxCBORDepth+2; index++ {
		deep = append(deep, cborHeader(4, 1)...)
	}
	deep = append(deep, 0x01)
	if _, _, err := decodeCBOR(deep); err == nil {
		t.Fatal("decodeCBOR accepted input nested past the depth bound")
	}
}

func FuzzDecodeCBORNeverPanics(f *testing.F) {
	device := &fakeAuthenticator{credentialID: make([]byte, 4)}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	device.key = key
	f.Add(device.attestationObject(AttestationNone, testRPID, flagUserPresent|flagAttestedCredData))
	f.Add(device.coseKey())
	f.Add([]byte{0xbf, 0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		_, _, _ = decodeCBOR(input)
	})
}

func FuzzVerifyPasskeyRegistrationNeverPanics(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	device := &fakeAuthenticator{key: key, credentialID: make([]byte, 16)}
	f.Add(device.attestationObject(AttestationNone, testRPID, flagUserPresent|flagAttestedCredData),
		[]byte(`{"type":"webauthn.create","challenge":"x","origin":"https://id.example"}`))
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, attestation, client []byte) {
		_, _ = VerifyPasskeyRegistration(attestation, client, "x", testOrigin, testRPID)
	})
}
