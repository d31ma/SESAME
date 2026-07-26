// Passkeys.
//
// A passkey is the only factor SESAME supports that is phishing-resistant by
// construction. The browser signs over the origin it is actually talking to,
// so a convincing replica of the login page cannot obtain a usable assertion —
// the signature it collects names the attacker's origin and fails here.
//
// Scope is deliberately narrow and stated rather than implied:
//
//   - attestation format "none" only. Attestation statements assert what kind
//     of hardware holds the key; verifying them means shipping and rotating
//     vendor root certificates, and for passkeys the platform guidance is not
//     to require it. SESAME refuses any other format rather than accepting it
//     unverified, which would be worse than not asking.
//   - COSE ES256 only, matching the token signing boundary. One algorithm
//     means nothing to negotiate and nothing to confuse.
//
// Everything security-relevant in an assertion is checked here: the challenge
// is single-use and supplied by the engine, the origin and RP ID must match
// the deployment exactly, the user-presence flag must be set, and a sign
// counter that fails to advance is treated as a cloned authenticator.
package authenticator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	// EventPasskeyRegistered records a new passkey bound to a principal.
	EventPasskeyRegistered = "authenticator.passkey_registered"
	// EventPasskeyUsed records a successful assertion. It carries the new
	// sign counter, which is what makes clone detection survive a restart.
	EventPasskeyUsed = "authenticator.passkey_used"
	// EventPasskeyRemoved records a durable, replay-safe unregistration —
	// the response to a lost or stolen authenticator.
	EventPasskeyRemoved = "authenticator.passkey_removed"

	// AttestationNone is the only attestation format SESAME accepts.
	AttestationNone = "none"

	// coseAlgorithmES256 is the only COSE algorithm SESAME accepts.
	coseAlgorithmES256 = -7
	coseKeyTypeEC2     = 2
	coseCurveP256      = 1

	// WebAuthn client data types.
	clientDataTypeCreate = "webauthn.create"
	clientDataTypeGet    = "webauthn.get"

	// Authenticator data flag bits (WebAuthn section 6.1).
	flagUserPresent      = 0x01
	flagUserVerified     = 0x04
	flagAttestedCredData = 0x40

	authenticatorDataMinLength = 37
	challengeBytes             = 32
	maxCredentialIDLength      = 1023
	maxClientDataLength        = 8192
	maxAttestationLength       = 16384
)

// Passkey is one registered credential.
//
// PublicKey is the stored ES256 key in uncompressed SEC1 form. SignCount is
// the last counter the authenticator reported; it is the only mutable part.
type Passkey struct {
	CredentialID string `json:"credential_id"`
	PrincipalID  string `json:"principal_id"`
	TenantID     string `json:"tenant_id"`
	PublicKey    string `json:"public_key"`
	SignCount    uint32 `json:"sign_count"`
	// UserVerified records whether the authenticator verified the user at
	// registration. It is advisory; each assertion carries its own flag.
	UserVerified bool   `json:"user_verified"`
	RegisteredAt string `json:"registered_at"`
}

// PasskeyRegisteredPayload is the versioned payload of
// EventPasskeyRegistered. Every field is a scalar, per FYLO's document model.
type PasskeyRegisteredPayload struct {
	CredentialID string `json:"credential_id"`
	PrincipalID  string `json:"principal_id"`
	TenantID     string `json:"tenant_id"`
	PublicKey    string `json:"public_key"`
	SignCount    uint32 `json:"sign_count"`
	UserVerified bool   `json:"user_verified"`
	RegisteredAt string `json:"registered_at"`
}

// PasskeyUsedPayload is the versioned payload of EventPasskeyUsed.
type PasskeyUsedPayload struct {
	CredentialID string `json:"credential_id"`
	PrincipalID  string `json:"principal_id"`
	TenantID     string `json:"tenant_id"`
	SignCount    uint32 `json:"sign_count"`
	UserVerified bool   `json:"user_verified"`
}

// PasskeyRemovedPayload is the versioned payload of EventPasskeyRemoved.
type PasskeyRemovedPayload struct {
	CredentialID string `json:"credential_id"`
	PrincipalID  string `json:"principal_id"`
	TenantID     string `json:"tenant_id"`
}

// Stable passkey errors.
var (
	ErrPasskeyUnsupportedAttestation = errors.New("only the none attestation format is supported")
	ErrPasskeyUnsupportedAlgorithm   = errors.New("only COSE ES256 passkeys are supported")
	ErrPasskeyInvalidClientData      = errors.New("passkey client data is not valid for this request")
	ErrPasskeyInvalidAuthData        = errors.New("passkey authenticator data is not valid")
	ErrPasskeyInvalidSignature       = errors.New("passkey assertion signature is not valid")
	ErrPasskeyCloned                 = errors.New("passkey sign counter did not advance; the authenticator may be cloned")
)

// NewPasskeyChallenge returns a fresh challenge for a registration or
// assertion. The engine supplies it; a challenge chosen by the browser would
// let a replayed assertion pass.
func NewPasskeyChallenge() (string, error) {
	value := make([]byte, challengeBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate passkey challenge: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// RelyingPartyID derives the RP ID from an issuer URL. WebAuthn scopes a
// credential to a domain, and the issuer's host is the domain SESAME already
// identifies itself by.
func RelyingPartyID(issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("cannot derive a relying party ID from issuer %q", issuer)
	}
	return parsed.Hostname(), nil
}

// clientData is the browser's account of what it was asked to sign.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// verifyClientData checks the browser's account against what the engine
// actually asked for.
//
// The origin comparison is the phishing resistance: the browser reports the
// origin it was really talking to, so an assertion collected by a replica of
// the login page names the replica and is refused here.
func verifyClientData(raw []byte, expectedType, expectedChallenge, expectedOrigin string) error {
	if len(raw) == 0 || len(raw) > maxClientDataLength {
		return fmt.Errorf("%w: client data is empty or oversized", ErrPasskeyInvalidClientData)
	}
	var parsed clientData
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		// Browsers may add fields (tokenBinding, topOrigin). Retry leniently
		// rather than rejecting a conforming client, but only after the
		// strict attempt, so the common case stays strict.
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return fmt.Errorf("%w: %v", ErrPasskeyInvalidClientData, err)
		}
	}
	if parsed.Type != expectedType {
		return fmt.Errorf("%w: type is %q, want %q", ErrPasskeyInvalidClientData, parsed.Type, expectedType)
	}
	// Constant time because the challenge is a secret the caller is proving
	// knowledge of.
	if subtle.ConstantTimeCompare([]byte(parsed.Challenge), []byte(expectedChallenge)) != 1 {
		return fmt.Errorf("%w: challenge does not match", ErrPasskeyInvalidClientData)
	}
	if parsed.Origin != expectedOrigin {
		return fmt.Errorf("%w: origin %q is not %q", ErrPasskeyInvalidClientData, parsed.Origin, expectedOrigin)
	}
	if parsed.CrossOrigin {
		// A credential used from inside a cross-origin frame is a credential
		// used somewhere the user cannot see.
		return fmt.Errorf("%w: cross-origin use is refused", ErrPasskeyInvalidClientData)
	}
	return nil
}

// authenticatorData is the fixed-layout binary preamble every authenticator
// signs over.
type authenticatorData struct {
	RPIDHash     []byte
	UserPresent  bool
	UserVerified bool
	SignCount    uint32
	CredentialID []byte
	PublicKey    []byte
	Raw          []byte
}

// parseAuthenticatorData reads the binary layout from WebAuthn section 6.1.
func parseAuthenticatorData(raw []byte, expectRPID string, wantCredential bool) (authenticatorData, error) {
	if len(raw) < authenticatorDataMinLength {
		return authenticatorData{}, fmt.Errorf("%w: shorter than %d bytes", ErrPasskeyInvalidAuthData, authenticatorDataMinLength)
	}
	data := authenticatorData{
		RPIDHash:     raw[:32],
		UserPresent:  raw[32]&flagUserPresent != 0,
		UserVerified: raw[32]&flagUserVerified != 0,
		SignCount:    binary.BigEndian.Uint32(raw[33:37]),
		Raw:          raw,
	}

	expected := sha256.Sum256([]byte(expectRPID))
	if subtle.ConstantTimeCompare(data.RPIDHash, expected[:]) != 1 {
		return authenticatorData{}, fmt.Errorf("%w: relying party ID does not match", ErrPasskeyInvalidAuthData)
	}
	// User presence means a human touched the authenticator. Without it the
	// assertion could have been produced by malware on the device.
	if !data.UserPresent {
		return authenticatorData{}, fmt.Errorf("%w: user presence flag is not set", ErrPasskeyInvalidAuthData)
	}

	if !wantCredential {
		return data, nil
	}
	if raw[32]&flagAttestedCredData == 0 {
		return authenticatorData{}, fmt.Errorf("%w: registration carries no credential data", ErrPasskeyInvalidAuthData)
	}

	rest := raw[authenticatorDataMinLength:]
	// 16 bytes AAGUID, then a 2-byte credential ID length.
	if len(rest) < 18 {
		return authenticatorData{}, fmt.Errorf("%w: truncated credential data", ErrPasskeyInvalidAuthData)
	}
	idLength := int(binary.BigEndian.Uint16(rest[16:18]))
	if idLength == 0 || idLength > maxCredentialIDLength {
		return authenticatorData{}, fmt.Errorf("%w: credential ID length %d", ErrPasskeyInvalidAuthData, idLength)
	}
	rest = rest[18:]
	if len(rest) < idLength {
		return authenticatorData{}, fmt.Errorf("%w: truncated credential ID", ErrPasskeyInvalidAuthData)
	}
	data.CredentialID = rest[:idLength]

	publicKey, err := parseCOSEKey(rest[idLength:])
	if err != nil {
		return authenticatorData{}, err
	}
	data.PublicKey = publicKey
	return data, nil
}

// parseCOSEKey extracts an ES256 public key in uncompressed SEC1 form.
func parseCOSEKey(raw []byte) ([]byte, error) {
	decoded, _, err := decodeCBOR(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasskeyInvalidAuthData, err)
	}
	keyType, ok := decoded.lookupLabel(1)
	if !ok {
		return nil, fmt.Errorf("%w: COSE key has no type", ErrPasskeyUnsupportedAlgorithm)
	}
	algorithm, ok := decoded.lookupLabel(3)
	if !ok {
		return nil, fmt.Errorf("%w: COSE key has no algorithm", ErrPasskeyUnsupportedAlgorithm)
	}
	keyTypeValue, keyTypeOK := keyType.integer()
	algorithmValue, algorithmOK := algorithm.integer()
	if !keyTypeOK || !algorithmOK || keyTypeValue != coseKeyTypeEC2 || algorithmValue != coseAlgorithmES256 {
		return nil, fmt.Errorf("%w: key type %v algorithm %v", ErrPasskeyUnsupportedAlgorithm, keyTypeValue, algorithmValue)
	}
	curve, ok := decoded.lookupLabel(-1)
	if curveValue, curveOK := curve.integer(); !ok || !curveOK || curveValue != coseCurveP256 {
		return nil, fmt.Errorf("%w: curve is not P-256", ErrPasskeyUnsupportedAlgorithm)
	}
	x, xOK := decoded.lookupLabel(-2)
	y, yOK := decoded.lookupLabel(-3)
	if !xOK || !yOK || x.kind != cborBytes || y.kind != cborBytes ||
		len(x.bytes) != 32 || len(y.bytes) != 32 {
		return nil, fmt.Errorf("%w: coordinates are not 32 bytes", ErrPasskeyUnsupportedAlgorithm)
	}

	point := make([]byte, 0, 65)
	point = append(point, 4)
	point = append(point, x.bytes...)
	point = append(point, y.bytes...)
	// Reject a point that is not on the curve rather than storing it and
	// discovering the problem at every future assertion.
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point); err != nil {
		return nil, fmt.Errorf("%w: public key is not on P-256", ErrPasskeyUnsupportedAlgorithm)
	}
	return point, nil
}

// RegisteredPasskey is the result of verifying a registration.
type RegisteredPasskey struct {
	CredentialID string
	PublicKey    string
	SignCount    uint32
	UserVerified bool
}

// VerifyPasskeyRegistration checks an attestation object and returns the
// credential to store.
//
// The attestation format must be "none". Any other format is refused rather
// than accepted without verifying its statement, because an unverified
// attestation is a claim about hardware that nothing checked.
func VerifyPasskeyRegistration(
	attestationObject []byte,
	clientDataJSON []byte,
	expectedChallenge string,
	expectedOrigin string,
	relyingPartyID string,
) (RegisteredPasskey, error) {
	if len(attestationObject) == 0 || len(attestationObject) > maxAttestationLength {
		return RegisteredPasskey{}, fmt.Errorf("%w: attestation object is empty or oversized", ErrPasskeyInvalidAuthData)
	}
	if err := verifyClientData(clientDataJSON, clientDataTypeCreate, expectedChallenge, expectedOrigin); err != nil {
		return RegisteredPasskey{}, err
	}

	decoded, _, err := decodeCBOR(attestationObject)
	if err != nil {
		return RegisteredPasskey{}, fmt.Errorf("%w: %v", ErrPasskeyInvalidAuthData, err)
	}
	format, ok := decoded.lookupText("fmt")
	if !ok || format.kind != cborText {
		return RegisteredPasskey{}, fmt.Errorf("%w: attestation object has no format", ErrPasskeyInvalidAuthData)
	}
	if format.text != AttestationNone {
		return RegisteredPasskey{}, fmt.Errorf("%w: got %q", ErrPasskeyUnsupportedAttestation, format.text)
	}
	rawAuthData, ok := decoded.lookupText("authData")
	if !ok || rawAuthData.kind != cborBytes {
		return RegisteredPasskey{}, fmt.Errorf("%w: attestation object has no authenticator data", ErrPasskeyInvalidAuthData)
	}

	data, err := parseAuthenticatorData(rawAuthData.bytes, relyingPartyID, true)
	if err != nil {
		return RegisteredPasskey{}, err
	}
	return RegisteredPasskey{
		CredentialID: base64.RawURLEncoding.EncodeToString(data.CredentialID),
		PublicKey:    base64.RawURLEncoding.EncodeToString(data.PublicKey),
		SignCount:    data.SignCount,
		UserVerified: data.UserVerified,
	}, nil
}

// AssertedPasskey is the result of verifying an assertion.
type AssertedPasskey struct {
	SignCount    uint32
	UserVerified bool
}

// VerifyPasskeyAssertion checks a signed assertion against a stored
// credential.
//
// The signature covers the authenticator data concatenated with the SHA-256
// of the client data, so one signature commits to the RP ID, the flags, the
// counter, the challenge, and the origin together. None of them can be
// substituted independently.
func VerifyPasskeyAssertion(
	stored Passkey,
	authenticatorDataRaw []byte,
	clientDataJSON []byte,
	signature []byte,
	expectedChallenge string,
	expectedOrigin string,
	relyingPartyID string,
) (AssertedPasskey, error) {
	if err := verifyClientData(clientDataJSON, clientDataTypeGet, expectedChallenge, expectedOrigin); err != nil {
		return AssertedPasskey{}, err
	}
	data, err := parseAuthenticatorData(authenticatorDataRaw, relyingPartyID, false)
	if err != nil {
		return AssertedPasskey{}, err
	}

	publicKey, err := decodePasskeyPublicKey(stored.PublicKey)
	if err != nil {
		return AssertedPasskey{}, err
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authenticatorDataRaw)+len(clientDataHash))
	signed = append(signed, authenticatorDataRaw...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return AssertedPasskey{}, ErrPasskeyInvalidSignature
	}

	// A counter that does not advance means two authenticators are answering
	// for one credential — the signal WebAuthn provides for a cloned key.
	// Many passkeys report a constant zero, and zero-to-zero is the
	// documented "counter not supported" case rather than a clone.
	if !(stored.SignCount == 0 && data.SignCount == 0) && data.SignCount <= stored.SignCount {
		return AssertedPasskey{}, fmt.Errorf("%w: %d did not advance past %d",
			ErrPasskeyCloned, data.SignCount, stored.SignCount)
	}

	return AssertedPasskey{SignCount: data.SignCount, UserVerified: data.UserVerified}, nil
}

func decodePasskeyPublicKey(encoded string) (*ecdsa.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 65 || raw[0] != 4 {
		return nil, fmt.Errorf("%w: stored public key is malformed", ErrPasskeyUnsupportedAlgorithm)
	}
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, fmt.Errorf("%w: stored public key is not on P-256", ErrPasskeyUnsupportedAlgorithm)
	}
	return public, nil
}

// ValidateCredentialID rejects values that cannot be credential identifiers.
func ValidateCredentialID(id string) error {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) == 0 || len(raw) > maxCredentialIDLength {
		return errors.New("credential ID must be non-empty base64url within the WebAuthn length bound")
	}
	return nil
}
