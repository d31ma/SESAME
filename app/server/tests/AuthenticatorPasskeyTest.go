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

	"github.com/d31ma/sesame/app/server/packages/sesame"
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
	authn := &AuthnController{engineService: controller.tenantCallService.engineService}

	stored := test.register(controller, setup.SignedIn(session), key)
	listed, listErr := controller.PostPasskeyList(setup.SignedIn(session))
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
	request := setup.SignedIn(session)
	challenge, _ := controller.PostPasskeyRegisterBegin(request)
	attestation := test.attestation(challenge, key)
	controller.PostPasskeyRegisterFinish(request, attestation)

	replayed, err := controller.PostPasskeyRegisterFinish(request, attestation)

	Assert.Equals(http.StatusBadRequest, setup.Status(err))
	Assert.Equals("", replayed.CredentialID)
}

func (test *AuthenticatorPasskeyTest) TestRemovedPasskeyNoLongerSignsIn() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", false)
	key := test.key()
	controller := test.controller()
	authn := &AuthnController{engineService: controller.tenantCallService.engineService}
	stored := test.register(controller, setup.SignedIn(session), key)

	removal, err := controller.PostPasskeyRemove(
		setup.SignedIn(session),
		AuthenticatorPasskeyRemoveRequest{CredentialID: stored.CredentialID},
	)
	listed, _ := controller.PostPasskeyList(setup.SignedIn(session))
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
	stored := test.register(controller, setup.SignedIn(owner), test.key())

	_, foreignErr := controller.PostPasskeyRemove(
		setup.SignedIn(intruder),
		AuthenticatorPasskeyRemoveRequest{CredentialID: stored.CredentialID},
	)
	_, unknownErr := controller.PostPasskeyRemove(
		setup.SignedIn(intruder),
		AuthenticatorPasskeyRemoveRequest{CredentialID: test.encode(test.randomBytes())},
	)
	ownerList, _ := controller.PostPasskeyList(setup.SignedIn(owner))
	intruderList, _ := controller.PostPasskeyList(setup.SignedIn(intruder))

	Assert.Equals(http.StatusNotFound, setup.Status(foreignErr))
	Assert.Equals(test.answer(unknownErr), test.answer(foreignErr))
	Assert.Equals(`{"code":"passkey_not_found"}`, test.answer(foreignErr))
	Assert.Equals(1, len(ownerList.Passkeys))
	Assert.Equals(0, len(intruderList.Passkeys))
}

func (test *AuthenticatorPasskeyTest) TestAdministratorListsAndRemovesAMembersPasskey() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	member := setup.SignInMember("acme", "member")
	controller := test.controller()
	stored := test.register(controller, setup.SignedIn(member), test.key())

	listed, listErr := controller.PostPasskeyListForPrincipal(
		setup.SignedIn(administrator),
		PrincipalReference{PrincipalID: member.PrincipalID},
	)
	removal, err := controller.PostPasskeyRemoveForPrincipal(
		setup.SignedIn(administrator),
		AuthenticatorPasskeyRemoveForPrincipalRequest{PrincipalID: member.PrincipalID, CredentialID: stored.CredentialID},
	)
	remaining, _ := controller.PostPasskeyList(setup.SignedIn(member))

	Assert.IsTrue(listErr == nil)
	Assert.Equals(1, len(listed.Passkeys))
	Assert.IsTrue(err == nil)
	Assert.IsTrue(removal.Removed)
	Assert.Equals(0, len(remaining.Passkeys))
}

func (test *AuthenticatorPasskeyTest) TestAdministratorRemovalNamesTheOwnerOfThePasskey() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	owner := setup.SignInMember("acme", "owner")
	bystander := setup.SignInMember("acme", "bystander")
	controller := test.controller()
	stored := test.register(controller, setup.SignedIn(owner), test.key())

	_, err := controller.PostPasskeyRemoveForPrincipal(
		setup.SignedIn(administrator),
		AuthenticatorPasskeyRemoveForPrincipalRequest{PrincipalID: bystander.PrincipalID, CredentialID: stored.CredentialID},
	)
	remaining, _ := controller.PostPasskeyList(setup.SignedIn(owner))

	Assert.Equals(http.StatusNotFound, setup.Status(err))
	Assert.Equals(`{"code":"passkey_not_found"}`, test.answer(err))
	Assert.Equals(1, len(remaining.Passkeys))
}

func (test *AuthenticatorPasskeyTest) TestAdministratorCannotReachAnotherTenantsPasskeys() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	administrator := setup.SignIn("acme", true)
	stranger := setup.SignIn("globex", false)
	controller := test.controller()
	stored := test.register(controller, setup.SignedIn(stranger), test.key())

	listed, listErr := controller.PostPasskeyListForPrincipal(
		setup.SignedIn(administrator),
		PrincipalReference{PrincipalID: stranger.PrincipalID},
	)
	_, removeErr := controller.PostPasskeyRemoveForPrincipal(
		setup.SignedIn(administrator),
		AuthenticatorPasskeyRemoveForPrincipalRequest{PrincipalID: stranger.PrincipalID, CredentialID: stored.CredentialID},
	)
	remaining, _ := controller.PostPasskeyList(setup.SignedIn(stranger))

	Assert.Equals(`{"code":"tenant_mismatch"}`, test.answer(listErr))
	Assert.Equals(0, len(listed.Passkeys))
	Assert.Equals(`{"code":"tenant_mismatch"}`, test.answer(removeErr))
	Assert.Equals(1, len(remaining.Passkeys))
}

func (test *AuthenticatorPasskeyTest) register(
	controller *AuthenticatorController,
	request *http.Request,
	key *ecdsa.PrivateKey,
) AuthenticatorPasskey {
	challenge, err := controller.PostPasskeyRegisterBegin(request)
	SesameTestSetup{}.Check(err)
	stored, err := controller.PostPasskeyRegisterFinish(request, test.attestation(challenge, key))
	SesameTestSetup{}.Check(err)
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
	SesameTestSetup{}.Check(err)
	options, err := authn.PostPasskeyOptions(AuthnTransactionRequest{TransactionID: begun.TransactionID})
	SesameTestSetup{}.Check(err)
	authenticatorData := test.authenticatorData(options.RelyingPartyID, 0x01|0x04, 1)
	clientData := test.clientData("webauthn.get", options.Challenge, options.Origin)
	verified, err := authn.PostVerifyPasskey(AuthnVerifyPasskeyRequest{
		TransactionID:     begun.TransactionID,
		CredentialID:      credentialID,
		AuthenticatorData: test.encode(authenticatorData),
		ClientDataJSON:    test.encode(clientData),
		Signature:         test.encode(test.sign(key, authenticatorData, clientData)),
	})
	SesameTestSetup{}.Check(err)
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
	SesameTestSetup{}.Check(err)
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
	SesameTestSetup{}.Check(err)
	return encoded
}

func (test *AuthenticatorPasskeyTest) sign(key *ecdsa.PrivateKey, authenticatorData []byte, clientData []byte) []byte {
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authenticatorData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	SesameTestSetup{}.Check(err)
	return signature
}

func (test *AuthenticatorPasskeyTest) key() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	SesameTestSetup{}.Check(err)
	return key
}

func (test *AuthenticatorPasskeyTest) randomBytes() []byte {
	value := make([]byte, 20)
	_, err := rand.Read(value)
	SesameTestSetup{}.Check(err)
	return value
}

func (test *AuthenticatorPasskeyTest) encode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func (test *AuthenticatorPasskeyTest) answer(err error) string {
	body, _ := io.ReadAll((&SesameErrorHandler{}).Answer(err).Body)
	return string(body)
}

func (test *AuthenticatorPasskeyTest) controller() *AuthenticatorController {
	engine := &EngineService{engineSettingsService: &EngineSettingsService{}}
	calls := &TenantCallService{
		callerService:        &CallerService{engineService: engine},
		engineService:        engine,
		administratorService: &AdministratorService{engineService: engine},
		recentSignInService:  &RecentSignInService{},
	}
	return &AuthenticatorController{
		tenantCallService:      calls,
		principalTenantService: &PrincipalTenantService{tenantCallService: calls},
	}
}
