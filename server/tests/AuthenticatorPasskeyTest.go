import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/d31ma/sesame/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type AuthenticatorPasskeyTest struct {
	behaviors *BehaviorContext
}

func (test *AuthenticatorPasskeyTest) TestRegisteredPasskeySignsTheCallerInWithMfa() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)
	key := test.key()
	controller := test.controller()
	authn := &AuthnController{engineService: controller.engineService}

	stored := test.register(controller, test.request(setup, session), key)
	listed, listErr := controller.PostPasskeyList(test.request(setup, session))
	verified := test.loginWithPasskey(authn, session, key, stored.CredentialID)
	issued, completeErr := authn.PostComplete(AuthnCompleteRequest{TransactionID: verified.TransactionID})

	Assert.Equals(session.PrincipalID, stored.PrincipalID)
	Assert.IsTrue(listErr == nil)
	Assert.Equals(1, len(listed.Passkeys))
	Assert.Equals(stored.CredentialID, listed.Passkeys[0].CredentialID)
	Assert.Equals("mfa", verified.Assurance)
	Assert.IsTrue(completeErr == nil)
	Assert.Equals(session.PrincipalID, issued.PrincipalID)
}

func (test *AuthenticatorPasskeyTest) TestRegistrationChallengeIsSpentOnFirstUse() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)
	key := test.key()
	controller := test.controller()
	request := test.request(setup, session)
	challenge, _ := controller.PostPasskeyRegisterBegin(request)
	attestation := test.attestation(challenge, key)
	controller.PostPasskeyRegisterFinish(request, attestation)

	replayed, err := controller.PostPasskeyRegisterFinish(request, attestation)

	Assert.Equals(http.StatusBadRequest, test.status(err))
	Assert.Equals("", replayed.CredentialID)
}

func (test *AuthenticatorPasskeyTest) TestRemovedPasskeyNoLongerSignsIn() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)
	key := test.key()
	controller := test.controller()
	authn := &AuthnController{engineService: controller.engineService}
	stored := test.register(controller, test.request(setup, session), key)

	removal, err := controller.PostPasskeyRemove(
		test.request(setup, session),
		AuthenticatorPasskeyRemoveRequest{CredentialID: stored.CredentialID},
	)
	listed, _ := controller.PostPasskeyList(test.request(setup, session))
	verified := test.loginWithPasskey(authn, session, key, stored.CredentialID)

	Assert.IsTrue(err == nil)
	Assert.IsTrue(removal.Removed)
	Assert.Equals(0, len(listed.Passkeys))
	Assert.Equals("", verified.Assurance)
}

func (test *AuthenticatorPasskeyTest) TestRemovingAnotherPrincipalsPasskeyAnswersLikeAnUnknownOne() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	owner := setup.SignIn("acme", false)
	intruder := setup.SignInMember("acme", "intruder")
	controller := test.controller()
	stored := test.register(controller, test.request(setup, owner), test.key())

	_, foreignErr := controller.PostPasskeyRemove(
		test.request(setup, intruder),
		AuthenticatorPasskeyRemoveRequest{CredentialID: stored.CredentialID},
	)
	_, unknownErr := controller.PostPasskeyRemove(
		test.request(setup, intruder),
		AuthenticatorPasskeyRemoveRequest{CredentialID: test.encode(test.randomBytes())},
	)
	ownerList, _ := controller.PostPasskeyList(test.request(setup, owner))
	intruderList, _ := controller.PostPasskeyList(test.request(setup, intruder))

	Assert.Equals(http.StatusNotFound, test.status(foreignErr))
	Assert.Equals(test.answer(unknownErr), test.answer(foreignErr))
	Assert.Equals(`{"code":"passkey_not_found"}`, test.answer(foreignErr))
	Assert.Equals(1, len(ownerList.Passkeys))
	Assert.Equals(0, len(intruderList.Passkeys))
}

func (test *AuthenticatorPasskeyTest) register(
	controller *AuthenticatorController,
	request *http.Request,
	key *ecdsa.PrivateKey,
) AuthenticatorPasskey {
	challenge, err := controller.PostPasskeyRegisterBegin(request)
	test.check(err)
	stored, err := controller.PostPasskeyRegisterFinish(request, test.attestation(challenge, key))
	test.check(err)
	return stored
}

func (test *AuthenticatorPasskeyTest) loginWithPasskey(
	authn *AuthnController,
	session sesame.IssuedSession,
	key *ecdsa.PrivateKey,
	credentialID string,
) AuthnTransaction {
	begun, err := authn.PostBegin(AuthnBeginRequest{
		TenantID:            session.TenantID,
		IdentifierNamespace: "email",
		IdentifierValue:     "person@acme.test",
	})
	test.check(err)
	options, err := authn.PostPasskeyOptions(AuthnTransactionRequest{TransactionID: begun.TransactionID})
	test.check(err)
	authenticatorData := test.authenticatorData(options.RelyingPartyID, 0x01|0x04, 1)
	clientData := test.clientData("webauthn.get", options.Challenge, options.Origin)
	verified, err := authn.PostVerifyPasskey(AuthnVerifyPasskeyRequest{
		TransactionID:     begun.TransactionID,
		CredentialID:      credentialID,
		AuthenticatorData: test.encode(authenticatorData),
		ClientDataJSON:    test.encode(clientData),
		Signature:         test.encode(test.sign(key, authenticatorData, clientData)),
	})
	test.check(err)
	return verified
}

func (test *AuthenticatorPasskeyTest) attestation(
	challenge AuthenticatorPasskeyChallenge,
	key *ecdsa.PrivateKey,
) AuthenticatorPasskeyAttestation {
	body := append(test.authenticatorData(challenge.RelyingPartyID, 0x01|0x04|0x40, 0), test.attestedCredential(key)...)
	object := test.head(5, 3)
	object = append(object, test.text("fmt")...)
	object = append(object, test.text("none")...)
	object = append(object, test.text("attStmt")...)
	object = append(object, test.head(5, 0)...)
	object = append(object, test.text("authData")...)
	object = append(object, append(test.head(2, uint64(len(body))), body...)...)
	return AuthenticatorPasskeyAttestation{
		AttestationObject: test.encode(object),
		ClientDataJSON:    test.encode(test.clientData("webauthn.create", challenge.Challenge, challenge.Origin)),
	}
}

func (test *AuthenticatorPasskeyTest) authenticatorData(relyingPartyID string, flags byte, counter uint32) []byte {
	hash := sha256.Sum256([]byte(relyingPartyID))
	data := append(hash[:], flags)
	return binary.BigEndian.AppendUint32(data, counter)
}

func (test *AuthenticatorPasskeyTest) attestedCredential(key *ecdsa.PrivateKey) []byte {
	credentialID := test.randomBytes()
	data := make([]byte, 16)
	data = binary.BigEndian.AppendUint16(data, uint16(len(credentialID)))
	data = append(data, credentialID...)
	return append(data, test.coseKey(key)...)
}

func (test *AuthenticatorPasskeyTest) coseKey(key *ecdsa.PrivateKey) []byte {
	point, err := key.PublicKey.Bytes()
	test.check(err)
	encoded := test.head(5, 5)
	encoded = append(encoded, append(test.head(0, 1), test.head(0, 2)...)...)
	encoded = append(encoded, append(test.head(0, 3), test.head(1, 6)...)...)
	encoded = append(encoded, append(test.head(1, 0), test.head(0, 1)...)...)
	encoded = append(encoded, test.head(1, 1)...)
	encoded = append(encoded, append(test.head(2, 32), point[1:33]...)...)
	encoded = append(encoded, test.head(1, 2)...)
	return append(encoded, append(test.head(2, 32), point[33:]...)...)
}

func (test *AuthenticatorPasskeyTest) head(major byte, argument uint64) []byte {
	switch {
	case argument < 24:
		return []byte{major<<5 | byte(argument)}
	case argument < 256:
		return []byte{major<<5 | 24, byte(argument)}
	}
	return []byte{major<<5 | 25, byte(argument >> 8), byte(argument)}
}

func (test *AuthenticatorPasskeyTest) text(value string) []byte {
	return append(test.head(3, uint64(len(value))), value...)
}

func (test *AuthenticatorPasskeyTest) clientData(kind string, challenge string, origin string) []byte {
	encoded, err := json.Marshal(map[string]any{
		"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false,
	})
	test.check(err)
	return encoded
}

func (test *AuthenticatorPasskeyTest) sign(key *ecdsa.PrivateKey, authenticatorData []byte, clientData []byte) []byte {
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authenticatorData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	test.check(err)
	return signature
}

func (test *AuthenticatorPasskeyTest) key() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.check(err)
	return key
}

func (test *AuthenticatorPasskeyTest) randomBytes() []byte {
	value := make([]byte, 20)
	_, err := rand.Read(value)
	test.check(err)
	return value
}

func (test *AuthenticatorPasskeyTest) encode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func (test *AuthenticatorPasskeyTest) request(setup *SesameTestSetup, session sesame.IssuedSession) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Sesame-Session", setup.Credential(session))
	return request
}

func (test *AuthenticatorPasskeyTest) status(err error) int {
	return (&SesameErrorHandler{}).Answer(err).StatusCode
}

func (test *AuthenticatorPasskeyTest) answer(err error) string {
	body, _ := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	return string(body)
}

func (test *AuthenticatorPasskeyTest) check(err error) {
	if err != nil {
		panic(err)
	}
}

func (test *AuthenticatorPasskeyTest) controller() *AuthenticatorController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	return &AuthenticatorController{callerService: &CallerService{engineService: engine}, engineService: engine}
}
