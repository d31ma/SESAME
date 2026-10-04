import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
	"github.com/d31ma/sesame/app/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type OidcControllerTest struct {
	behaviors *BehaviorContext
}

func (test *OidcControllerTest) TestInteractionCompleteIssuesACodeForTheCallersSession() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	cookie := test.authorize(engine, registered)
	signedIn := setup.SignedIn(session)

	interaction, getErr := test.controller(engine).PostInteractionGet(signedIn, cookie)
	completed, err := test.controller(engine).PostInteractionComplete(signedIn, cookie)
	replayed, replayErr := test.controller(engine).PostInteractionComplete(signedIn, cookie)

	Assert.IsTrue(getErr == nil)
	Assert.Equals(registered.Client.ID, interaction.ClientID)
	Assert.Equals("awaiting_authentication", interaction.Status)
	Assert.IsTrue(err == nil)
	Assert.IsTrue(completed.Code != "")
	Assert.Equals("https://rp.example/callback", completed.Redirect)
	Assert.Equals("state-value", completed.State)
	Assert.Equals("", replayed.Code)
	Assert.Equals("interaction_closed", setup.ProtocolCode(replayErr))
}

func (test *OidcControllerTest) TestAThirdPartyClientNeedsTheCallersConsent() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignInMember("acme", "member")
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "third_party")
	cookie := test.authorize(engine, registered)
	signedIn := setup.SignedIn(session)
	controller := test.controller(engine)

	_, refusedErr := controller.PostInteractionComplete(signedIn, cookie)
	consent, grantErr := controller.PostConsentGrant(signedIn, OidcConsentGrantRequest{ClientID: registered.Client.ID, Scopes: []string{"openid"}})
	completed, completeErr := controller.PostInteractionComplete(signedIn, cookie)
	stored, storedErr := controller.PostConsentGet(signedIn, OidcClientReference{ClientID: registered.Client.ID})
	withdrawn, withdrawErr := controller.PostConsentWithdraw(signedIn, OidcClientReference{ClientID: registered.Client.ID})

	Assert.Equals("consent_required", setup.ProtocolCode(refusedErr))
	Assert.IsTrue(grantErr == nil)
	Assert.Equals(session.PrincipalID, consent.PrincipalID)
	Assert.IsTrue(completeErr == nil)
	Assert.IsTrue(completed.Code != "")
	Assert.IsTrue(storedErr == nil)
	Assert.Equals(session.PrincipalID, stored.PrincipalID)
	Assert.Equals("openid", strings.Join(stored.Scopes, " "))
	Assert.IsTrue(withdrawErr == nil)
	Assert.IsTrue(withdrawn.Withdrawn)
}

func (test *OidcControllerTest) TestConsentActsOnlyForTheCallersOwnPrincipal() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	owner := setup.SignInMember("acme", "owner")
	other := setup.SignInMember("acme", "other")
	engine := setup.Engine()
	registered := test.register(engine, owner.TenantID, "third_party")
	controller := test.controller(engine)
	_, grantErr := controller.PostConsentGrant(setup.SignedIn(owner),
		OidcConsentGrantRequest{ClientID: registered.Client.ID, Scopes: []string{"openid"}})

	_, otherErr := controller.PostConsentGet(setup.SignedIn(other), OidcClientReference{ClientID: registered.Client.ID})
	_, withdrawErr := controller.PostConsentWithdraw(setup.SignedIn(other), OidcClientReference{ClientID: registered.Client.ID})
	kept, keptErr := controller.PostConsentGet(setup.SignedIn(owner), OidcClientReference{ClientID: registered.Client.ID})

	Assert.IsTrue(grantErr == nil)
	Assert.Equals("consent_not_found", setup.ProtocolCode(otherErr))
	Assert.Equals("consent_not_found", setup.ProtocolCode(withdrawErr))
	Assert.IsTrue(keptErr == nil)
	Assert.IsTrue(!kept.Withdrawn)
	Assert.Equals(owner.PrincipalID, kept.PrincipalID)
}

func (test *OidcControllerTest) TestAnotherTenantCannotUseTheInteraction() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	intruder := setup.SignIn("globex", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	cookie := test.authorize(engine, registered)
	controller := test.controller(engine)

	_, getErr := controller.PostInteractionGet(setup.SignedIn(intruder), cookie)
	stolen, completeErr := controller.PostInteractionComplete(setup.SignedIn(intruder), cookie)
	completed, ownerErr := controller.PostInteractionComplete(setup.SignedIn(session), cookie)

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(getErr, &mismatch))
	Assert.IsTrue(completeErr != nil)
	Assert.Equals("", stolen.Code)
	Assert.IsTrue(ownerErr == nil)
	Assert.IsTrue(completed.Code != "")
}

func (test *OidcControllerTest) TestSignedInRoutesRejectAnAnonymousCaller() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	engine := setup.Engine()
	controller := test.controller(engine)
	anonymous := httptest.NewRequest(http.MethodPost, "/", nil)

	_, completeErr := controller.PostInteractionComplete(anonymous, "int_1:secret")
	_, getErr := controller.PostInteractionGet(anonymous, "int_1:secret")
	_, consentErr := controller.PostConsentGrant(anonymous, OidcConsentGrantRequest{ClientID: "cli_1", Scopes: []string{"openid"}})
	_, deviceErr := controller.PostDeviceApprove(anonymous, OidcUserCodeRequest{UserCode: "ABCD-EFGH"})

	Assert.IsTrue(setup.SessionRejected(completeErr))
	Assert.IsTrue(setup.SessionRejected(getErr))
	Assert.IsTrue(setup.SessionRejected(consentErr))
	Assert.IsTrue(setup.SessionRejected(deviceErr))
}

func (test *OidcControllerTest) TestAForgedInteractionCookieIsRefused() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	identifier, _, _ := strings.Cut(test.authorize(engine, registered), ":")
	signedIn := setup.SignedIn(session)

	forged, forgedErr := test.controller(engine).PostInteractionComplete(signedIn, identifier+":not-the-secret")
	_, garbageErr := test.controller(engine).PostInteractionComplete(signedIn, "garbage")

	Assert.Equals("", forged.Code)
	Assert.IsTrue(forgedErr != nil)
	Assert.IsTrue(garbageErr != nil)
}

func (test *OidcControllerTest) TestInteractionGetAnswersAWrongOrMissingSecretLikeAnUnknownInteraction() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	identifier, _, _ := strings.Cut(test.authorize(engine, registered), ":")
	controller := test.controller(engine)
	signedIn := setup.SignedIn(session)

	forged, forgedErr := controller.PostInteractionGet(signedIn, identifier+":not-the-secret")
	bare, bareErr := controller.PostInteractionGet(signedIn, identifier)
	_, unknownErr := controller.PostInteractionGet(signedIn, test.unknownInteraction("not-the-secret"))

	Assert.Equals("", forged.ClientID)
	Assert.Equals("", bare.ClientID)
	Assert.Equals("interaction_not_found", setup.ProtocolCode(unknownErr))
	Assert.Equals(test.answer(unknownErr), test.answer(forgedErr))
	Assert.Equals(test.answer(unknownErr), test.answer(bareErr))
}

func (test *OidcControllerTest) TestAMalformedInteractionCookieAnswersLikeAnUnknownInteraction() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	identifier, secret, _ := strings.Cut(test.authorize(engine, registered), ":")
	controller := test.controller(engine)
	signedIn := setup.SignedIn(session)
	malformed := []string{"", "garbage", identifier + "%3A" + secret, identifier[1:] + ":" + secret}

	unknown := test.interactionAnswers(controller, signedIn, []string{test.unknownInteraction(secret)})
	answers := test.interactionAnswers(controller, signedIn, malformed)

	Assert.Equals("404 {\"code\":\"interaction_not_found\"} 404 {\"code\":\"interaction_not_found\"}\n", unknown)
	Assert.Equals(strings.Repeat(unknown, len(malformed)), answers)
}

func (test *OidcControllerTest) TestADeviceIsApprovedByTheCallerAndRedeemedAtTheTokenEndpoint() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignInMember("acme", "member")
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	controller := test.controller(engine)
	signedIn := setup.SignedIn(session)
	started, startErr := controller.PostDeviceAuthorize(OidcDeviceAuthorizeRequest{ClientID: registered.Client.ID, Scopes: []string{"openid"}})

	pending, lookupErr := controller.PostDeviceLookup(signedIn, OidcUserCodeRequest{UserCode: started.UserCode})
	approved, approveErr := controller.PostDeviceApprove(signedIn, OidcUserCodeRequest{UserCode: started.UserCode})
	tokens := test.redeemDevice(engine, registered, started.DeviceCode)

	Assert.IsTrue(startErr == nil)
	Assert.IsTrue(started.DeviceCode != "")
	Assert.IsTrue(lookupErr == nil)
	Assert.Equals("Portal", pending.ClientName)
	Assert.IsTrue(approveErr == nil)
	Assert.Equals(started.DeviceAuthorizationID, approved.DeviceAuthorizationID)
	Assert.IsTrue(tokens["access_token"] != nil)
}

func (test *OidcControllerTest) TestADeviceCodeIsInvisibleToAnotherTenantAndCanBeDenied() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignInMember("acme", "member")
	intruder := setup.SignInMember("globex", "member")
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	controller := test.controller(engine)
	started, _ := controller.PostDeviceAuthorize(OidcDeviceAuthorizeRequest{ClientID: registered.Client.ID, Scopes: []string{"openid"}})
	code := OidcUserCodeRequest{UserCode: started.UserCode}

	_, lookupErr := controller.PostDeviceLookup(setup.SignedIn(intruder), code)
	_, approveErr := controller.PostDeviceApprove(setup.SignedIn(intruder), code)
	denied, denyErr := controller.PostDeviceDeny(setup.SignedIn(session), code)
	tokens := test.redeemDevice(engine, registered, started.DeviceCode)

	Assert.Equals("user_code_not_found", setup.ProtocolCode(lookupErr))
	Assert.Equals("user_code_not_found", setup.ProtocolCode(approveErr))
	Assert.IsTrue(denyErr == nil)
	Assert.IsTrue(denied.Denied)
	Assert.Equals("access_denied", tokens["error"])
}

func (test *OidcControllerTest) TestAPushedRequestStartsTheBrowserInteraction() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	request := test.pushed(registered, registered.Secret)

	pushed, err := test.controller(engine).PostPushedAuthorize(request)
	refused, refusedErr := test.controller(engine).PostPushedAuthorize(test.pushed(registered, "wrong-secret"))
	response, _ := test.standards(engine).GetAuthorization(httptest.NewRequest(http.MethodGet,
		"/oidc/authorize?client_id="+registered.Client.ID+"&request_uri="+url.QueryEscape(pushed.RequestAddress), nil))

	Assert.IsTrue(err == nil)
	Assert.IsTrue(pushed.ExpiresIn > 0)
	Assert.Equals("", refused.RequestAddress)
	Assert.IsTrue(refusedErr != nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals(1, len(response.Cookies()))
}

func (test *OidcControllerTest) TestDpopVerifyAcceptsAFreshProofOnce() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := test.boundToken(engine, session, registered, key)
	resource := "https://sesame.test/resource"
	check := OidcDpopVerifyRequest{AccessToken: token, Proof: test.proof(key, http.MethodGet, resource, token), Method: http.MethodGet, Address: resource}

	verified, err := test.controller(engine).PostDpopVerify(check)
	replayed, replayErr := test.controller(engine).PostDpopVerify(check)

	Assert.IsTrue(err == nil)
	Assert.IsTrue(verified.Active)
	Assert.Equals(session.PrincipalID, verified.PrincipalID)
	Assert.IsTrue(!replayed.Active)
	Assert.Equals("dpop_proof_replayed", setup.ProtocolCode(replayErr))
}

func (test *OidcControllerTest) TestRefreshFamilyRoutesAnswerAnUnknownFamily() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	controller := test.controller(setup.Engine())
	signedIn := setup.SignedIn(session)
	unknown := "rfm_00000000000000000000000000000000"

	_, getErr := controller.PostRefreshFamilyGet(signedIn, OidcRefreshFamilyReference{FamilyID: unknown})
	revoked, revokeErr := controller.PostRefreshFamilyRevoke(signedIn, OidcRefreshFamilyRevokeRequest{FamilyID: unknown})
	_, malformedErr := controller.PostRefreshFamilyGet(signedIn, OidcRefreshFamilyReference{FamilyID: "x"})

	Assert.Equals("refresh_family_not_found", setup.ProtocolCode(getErr))
	Assert.Equals("refresh_family_not_found", setup.ProtocolCode(revokeErr))
	Assert.IsTrue(!revoked.Revoked)
	Assert.Equals("invalid_request", setup.ProtocolCode(malformedErr))
}

func (test *OidcControllerTest) TestARefreshFamilyIsRevokedOnlyByItsTenantsAdministrator() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	intruder := setup.SignIn("globex", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	refreshToken := test.refreshToken(engine, session, registered)
	family := OidcRefreshFamilyReference{FamilyID: test.familyID(setup)}
	owner := setup.SignedIn(session)
	stranger := setup.SignedIn(intruder)
	controller := test.controller(engine)

	_, strangerGetErr := controller.PostRefreshFamilyGet(stranger, family)
	_, strangerRevokeErr := controller.PostRefreshFamilyRevoke(stranger, OidcRefreshFamilyRevokeRequest{FamilyID: family.FamilyID})
	before, beforeErr := controller.PostRefreshFamilyGet(owner, family)
	revoked, revokeErr := controller.PostRefreshFamilyRevoke(owner, OidcRefreshFamilyRevokeRequest{FamilyID: family.FamilyID, Reason: "lost device"})
	after, _ := controller.PostRefreshFamilyGet(owner, family)
	refreshed := test.refresh(engine, registered, refreshToken)

	var mismatch *host.TenantMismatchError
	Assert.IsTrue(errors.As(strangerGetErr, &mismatch))
	Assert.IsTrue(errors.As(strangerRevokeErr, &mismatch))
	Assert.IsTrue(beforeErr == nil)
	Assert.Equals(session.TenantID, before.TenantID)
	Assert.Equals(registered.Client.ID, before.ClientID)
	Assert.IsTrue(!before.Revoked)
	Assert.IsTrue(revokeErr == nil)
	Assert.IsTrue(revoked.Revoked)
	Assert.IsTrue(after.Revoked)
	Assert.Equals("invalid_grant", refreshed["error"])
}

func (test *OidcControllerTest) refreshToken(engine *EngineService, session sesame.IssuedSession, registered sesame.ClientRegistration) string {
	cookie := test.authorizeScope(engine, registered, "openid offline_access")
	completed, err := test.controller(engine).PostInteractionComplete(SesameTestSetup{}.Request(test.credential(session)), cookie)
	SesameTestSetup{}.Check(err)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", completed.Code)
	form.Set("redirect_uri", "https://rp.example/callback")
	form.Set("code_verifier", test.verifier())
	response, err := test.standards(engine).PostToken(test.clientPost(form, registered))
	SesameTestSetup{}.Check(err)
	token, _ := test.object(response)["refresh_token"].(string)
	return token
}

func (test *OidcControllerTest) refresh(engine *EngineService, registered sesame.ClientRegistration, refreshToken string) map[string]any {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	response, err := test.standards(engine).PostToken(test.clientPost(form, registered))
	SesameTestSetup{}.Check(err)
	return test.object(response)
}

func (test *OidcControllerTest) familyID(setup *SesameTestSetup) string {
	events := filepath.Join(setup.deployment, "fylo-root", ".collections", "sesame-security-events", "docs")
	found := ""
	_ = filepath.WalkDir(events, func(path string, entry os.DirEntry, err error) error {
		data, _ := os.ReadFile(path)
		found += string(regexp.MustCompile(`rfm_[0-9a-f]{32}`).Find(data))
		return nil
	})
	return found[:len("rfm_")+32]
}

func (test *OidcControllerTest) register(engine *EngineService, tenantID string, audience string) sesame.ClientRegistration {
	registered := sesame.ClientRegistration{}
	SesameTestSetup{}.Check(engine.Call("oidc_client.register", map[string]any{
		"tenant_id": tenantID, "name": "Portal", "client_type": "confidential",
		"redirect_uris": []string{"https://rp.example/callback"}, "scopes": []string{"openid", "offline_access"},
		"audience": audience,
	}, &registered))
	return registered
}

func (test *OidcControllerTest) authorize(engine *EngineService, registered sesame.ClientRegistration) string {
	return test.authorizeScope(engine, registered, "openid")
}

func (test *OidcControllerTest) authorizeScope(engine *EngineService, registered sesame.ClientRegistration, scope string) string {
	query := url.Values{}
	query.Set("client_id", registered.Client.ID)
	query.Set("redirect_uri", "https://rp.example/callback")
	query.Set("response_type", "code")
	query.Set("scope", scope)
	query.Set("state", "state-value")
	query.Set("code_challenge", test.challenge())
	query.Set("code_challenge_method", "S256")
	response, err := test.standards(engine).GetAuthorization(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+query.Encode(), nil))
	SesameTestSetup{}.Check(err)
	for _, cookie := range response.Cookies() {
		return cookie.Value
	}
	return ""
}

func (test *OidcControllerTest) pushed(registered sesame.ClientRegistration, secret string) OidcPushedAuthorizeRequest {
	return OidcPushedAuthorizeRequest{
		ClientID:            registered.Client.ID,
		ClientSecret:        secret,
		Redirect:            "https://rp.example/callback",
		ResponseType:        "code",
		Scopes:              []string{"openid"},
		CodeChallenge:       test.challenge(),
		CodeChallengeMethod: "S256",
	}
}

func (test *OidcControllerTest) boundToken(
	engine *EngineService,
	session sesame.IssuedSession,
	registered sesame.ClientRegistration,
	key *ecdsa.PrivateKey,
) string {
	cookie := test.authorize(engine, registered)
	completed, err := test.controller(engine).PostInteractionComplete(SesameTestSetup{}.Request(test.credential(session)), cookie)
	SesameTestSetup{}.Check(err)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", completed.Code)
	form.Set("redirect_uri", "https://rp.example/callback")
	form.Set("code_verifier", test.verifier())
	request := test.clientPost(form, registered)
	request.Host = "sesame.test"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("DPoP", test.proof(key, http.MethodPost, "https://sesame.test/oidc/token", ""))
	response, err := test.standards(engine).PostToken(request)
	SesameTestSetup{}.Check(err)
	token, _ := test.object(response)["access_token"].(string)
	return token
}

func (test *OidcControllerTest) redeemDevice(engine *EngineService, registered sesame.ClientRegistration, deviceCode string) map[string]any {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	response, err := test.standards(engine).PostToken(test.clientPost(form, registered))
	SesameTestSetup{}.Check(err)
	return test.object(response)
}

func (test *OidcControllerTest) proof(key *ecdsa.PrivateKey, method string, uri string, accessToken string) string {
	point, _ := key.PublicKey.Bytes()
	claims := map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString([]byte(time.Now().String() + method)),
		"htm": method, "htu": uri, "iat": time.Now().Unix(),
	}
	if accessToken != "" {
		digest := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(digest[:])
	}
	header := SesameTestSetup{}.Segment(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
			"y": base64.RawURLEncoding.EncodeToString(point[33:]),
		},
	})
	payload := SesameTestSetup{}.Segment(claims)
	digest := sha256.Sum256([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	SesameTestSetup{}.Check(err)
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (test *OidcControllerTest) challenge() string {
	digest := sha256.Sum256([]byte(test.verifier()))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (test *OidcControllerTest) verifier() string {
	return strings.Repeat("v", 50)
}

func (test *OidcControllerTest) clientPost(form url.Values, registered sesame.ClientRegistration) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(registered.Client.ID, registered.Secret)
	return request
}

func (test *OidcControllerTest) object(response *http.Response) map[string]any {
	decoded := map[string]any{}
	body, _ := io.ReadAll(response.Body)
	_ = json.Unmarshal(body, &decoded)
	return decoded
}

func (test *OidcControllerTest) interactionAnswers(controller *OidcController, request *http.Request, cookies []string) string {
	answers := ""
	for _, cookie := range cookies {
		_, getErr := controller.PostInteractionGet(request, cookie)
		_, completeErr := controller.PostInteractionComplete(request, cookie)
		answers += test.answer(getErr) + " " + test.answer(completeErr) + "\n"
	}
	return answers
}

func (test *OidcControllerTest) unknownInteraction(secret string) string {
	return "int_00000000000000000000000000000000:" + secret
}

func (test *OidcControllerTest) answer(err error) string {
	answer := (&SesameErrorHandler{}).Answer(err)
	body, _ := io.ReadAll(answer.Body)
	return fmt.Sprint(answer.StatusCode, " ", string(body))
}

func (test *OidcControllerTest) credential(session sesame.IssuedSession) string {
	return session.SessionID + ":" + session.Secret
}

func (test *OidcControllerTest) controller(engine *EngineService) *OidcController {
	return &OidcController{
		engineService:     engine,
		tenantCallService: SesameTestSetup{}.TenantCalls(engine),
	}
}

func (test *OidcControllerTest) standards(engine *EngineService) *StandardsController {
	return &StandardsController{
		standardsDispatchService: &StandardsDispatchService{engineService: engine},
		standardsAnswerService:   &StandardsAnswerService{},
	}
}
