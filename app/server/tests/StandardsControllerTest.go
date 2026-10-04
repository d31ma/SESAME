import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
	"github.com/d31ma/sesame/app/server/packages/sesame"
)

// @Test(SesameTestSetup, {"partition":"tests"})
type StandardsControllerTest struct {
	behaviors *BehaviorContext
}

func (test *StandardsControllerTest) TestDiscoveryPublishesTheHostRoutesUnderTheIssuer() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	engine := setup.Engine()

	response, err := test.controller(engine).GetDiscovery(test.get("/oidc/openid-configuration"))

	metadata := test.object(response)
	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals("https://sesame.test", metadata["issuer"])
	Assert.Equals("https://sesame.test/oidc/authorize", metadata["authorization_endpoint"])
	Assert.Equals("https://sesame.test/oidc/token", metadata["token_endpoint"])
	Assert.Equals("https://sesame.test/oidc/jwks", metadata["jwks_uri"])
	Assert.Equals("https://sesame.test/oidc/introspect", metadata["introspection_endpoint"])
	Assert.Equals("https://sesame.test/oidc/revoke", metadata["revocation_endpoint"])
	Assert.Equals("https://sesame.test/oidc/logout", metadata["end_session_endpoint"])
}

func (test *StandardsControllerTest) TestDiscoveryRefusesQueryParameters() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	engine := setup.Engine()

	response, err := test.controller(engine).GetDiscovery(test.get("/oidc/openid-configuration?x=1"))

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusBadRequest, response.StatusCode)
	Assert.Equals("invalid_request", test.object(response)["error"])
}

func (test *StandardsControllerTest) TestJwksPublishesTheSigningKey() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	engine := setup.Engine()

	response, err := test.controller(engine).GetJwks(test.get("/oidc/jwks"))

	keys, _ := test.object(response)["keys"].([]any)
	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals("application/json", response.Header.Get("Content-Type"))
	Assert.Equals(1, len(keys))
}

func (test *StandardsControllerTest) TestAuthorizationKeepsTheInteractionSecretInAnHttpOnlyCookie() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	tenantID := setup.SignIn("acme", true).TenantID
	engine := setup.Engine()
	registered := test.register(engine, tenantID, "first_party")

	response, err := test.controller(engine).GetAuthorization(test.get(test.authorizeTarget(registered, test.challenge("verifier"))))

	cookie := test.interactionCookie(response)
	identifier, secret, _ := strings.Cut(cookie.Value, ":")
	body := test.text(response)
	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals("no-store", response.Header.Get("Cache-Control"))
	Assert.IsTrue(cookie.HttpOnly)
	Assert.IsTrue(cookie.Secure)
	Assert.Equals("", cookie.Domain)
	Assert.Equals(http.SameSiteLaxMode, cookie.SameSite)
	Assert.Equals("/api/v1/oidc", cookie.Path)
	Assert.IsTrue(secret != "")
	Assert.IsTrue(!strings.Contains(body, secret))
	Assert.IsTrue(!strings.Contains(body, "interaction_secret"))
	Assert.IsTrue(strings.Contains(body, identifier))
	Assert.IsTrue(strings.Contains(body, "\"client_name\":\"Portal\""))
}

func (test *StandardsControllerTest) TestAuthorizationRefusesAnUnregisteredRedirectWithoutRedirecting() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	tenantID := setup.SignIn("acme", true).TenantID
	engine := setup.Engine()
	registered := test.register(engine, tenantID, "first_party")
	target := strings.Replace(test.authorizeTarget(registered, test.challenge("verifier")),
		url.QueryEscape(test.redirect()), url.QueryEscape("https://evil.example/callback"), 1)

	response, err := test.controller(engine).GetAuthorization(test.get(target))

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusBadRequest, response.StatusCode)
	Assert.Equals("", response.Header.Get("Location"))
	Assert.Equals(0, len(response.Cookies()))
	Assert.Equals("invalid_request", test.object(response)["error"])
}

func (test *StandardsControllerTest) TestTokenRedeemsACodeOnceAndIsNeverCached() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	code := test.code(engine, session, registered)
	form := test.codeForm(code, "verifier")

	first, firstErr := test.controller(engine).PostToken(test.clientPost("/oidc/token", form, registered))
	replayed, replayedErr := test.controller(engine).PostToken(test.clientPost("/oidc/token", form, registered))

	tokens := test.object(first)
	Assert.IsTrue(firstErr == nil)
	Assert.Equals(http.StatusOK, first.StatusCode)
	Assert.Equals("no-store", first.Header.Get("Cache-Control"))
	Assert.Equals("no-cache", first.Header.Get("Pragma"))
	Assert.Equals("Bearer", tokens["token_type"])
	Assert.IsTrue(tokens["id_token"] != nil)
	Assert.IsTrue(replayedErr == nil)
	Assert.Equals(http.StatusBadRequest, replayed.StatusCode)
	Assert.Equals("invalid_grant", test.object(replayed)["error"])
}

func (test *StandardsControllerTest) TestTokenRefusesADuplicatedParameter() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	code := test.code(engine, session, registered)

	response, err := test.controller(engine).PostToken(
		test.clientPost("/oidc/token", test.codeForm(code, "verifier")+"&code=again", registered))

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusBadRequest, response.StatusCode)
	Assert.Equals("invalid_request", test.object(response)["error"])
}

func (test *StandardsControllerTest) TestTokenRefusesTwoAuthorizationHeaders() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	engine := setup.Engine()
	request := test.post("/oidc/token", "grant_type=authorization_code")
	request.Header.Add("Authorization", "Basic one")
	request.Header.Add("Authorization", "Basic two")

	response, err := test.controller(engine).PostToken(request)

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusBadRequest, response.StatusCode)
	Assert.Equals("no-store", response.Header.Get("Cache-Control"))
	Assert.Equals("invalid_request", test.object(response)["error"])
}

func (test *StandardsControllerTest) TestTokenRefusesAnOversizedBody() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	engine := setup.Engine()

	response, err := test.controller(engine).PostToken(test.post("/oidc/token", "scope="+strings.Repeat("a", 128*1024)))

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusBadRequest, response.StatusCode)
	Assert.Equals("invalid_request", test.object(response)["error"])
}

func (test *StandardsControllerTest) TestTokenRefusesAWrongClientSecretWithoutEchoingIt() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	code := test.code(engine, session, registered)
	request := test.post("/oidc/token", test.codeForm(code, "verifier"))
	request.SetBasicAuth(registered.Client.ID, "wrong-secret-value")

	response, err := test.controller(engine).PostToken(request)

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusUnauthorized, response.StatusCode)
	Assert.IsTrue(response.Header.Get("WWW-Authenticate") != "")
	Assert.IsTrue(!strings.Contains(test.text(response), "wrong-secret-value"))
}

func (test *StandardsControllerTest) TestIntrospectionReportsAnActiveTokenToItsClient() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	tokens := test.tokens(engine, session, registered)

	response, err := test.controller(engine).PostIntrospection(
		test.clientPost("/oidc/introspect", "token="+url.QueryEscape(tokens["access_token"].(string)), registered))

	answer := test.object(response)
	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals("no-store", response.Header.Get("Cache-Control"))
	Assert.Equals(true, answer["active"])
	Assert.Equals(registered.Client.ID, answer["client_id"])
}

func (test *StandardsControllerTest) TestRevocationAcknowledgesWithAnEmptyTypedBody() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	tokens := test.tokens(engine, session, registered)

	response, err := test.controller(engine).PostRevocation(
		test.clientPost("/oidc/revoke", "token="+url.QueryEscape(tokens["refresh_token"].(string)), registered))
	refreshed, _ := test.controller(engine).PostToken(test.clientPost("/oidc/token",
		"grant_type=refresh_token&refresh_token="+url.QueryEscape(tokens["refresh_token"].(string)), registered))

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals("", test.text(response))
	Assert.Equals("text/plain; charset=utf-8", response.Header.Get("Content-Type"))
	Assert.Equals("no-store", response.Header.Get("Cache-Control"))
	Assert.Equals(http.StatusBadRequest, refreshed.StatusCode)
	Assert.Equals("invalid_grant", test.object(refreshed)["error"])
}

func (test *StandardsControllerTest) TestLogoutReturnsOnlyToARegisteredAddress() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	hint := url.QueryEscape(test.tokens(engine, session, registered)["id_token"].(string))

	refused, refusedErr := test.controller(engine).GetLogout(test.get("/oidc/logout?id_token_hint=" + hint +
		"&post_logout_redirect_uri=" + url.QueryEscape("https://evil.example/") + "&state=s"))
	accepted, acceptedErr := test.controller(engine).GetLogout(test.get("/oidc/logout?id_token_hint=" + hint +
		"&post_logout_redirect_uri=" + url.QueryEscape("https://rp.example/signed-out") + "&state=s"))

	Assert.IsTrue(refusedErr == nil)
	Assert.Equals(http.StatusBadRequest, refused.StatusCode)
	Assert.Equals("", refused.Header.Get("Location"))
	Assert.IsTrue(acceptedErr == nil)
	Assert.Equals(http.StatusSeeOther, accepted.StatusCode)
	Assert.Equals("https://rp.example/signed-out?state=s", accepted.Header.Get("Location"))
	Assert.Equals("no-store", accepted.Header.Get("Cache-Control"))
}

func (test *StandardsControllerTest) TestDpopBindsTheTokenToThePublicUriTachyonReports() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	code := test.code(engine, session, registered)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	request := test.clientPost("/oidc/token", test.codeForm(code, "verifier"), registered)
	request.Host = "sesame.test"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("DPoP", test.proof(key, "https://sesame.test/oidc/token"))

	response, err := test.controller(engine).PostToken(request)

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusOK, response.StatusCode)
	Assert.Equals("DPoP", test.object(response)["token_type"])
}

func (test *StandardsControllerTest) TestDpopRefusesAProofForAnotherUri() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	session := setup.SignIn("acme", true)
	engine := setup.Engine()
	registered := test.register(engine, session.TenantID, "first_party")
	code := test.code(engine, session, registered)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	request := test.clientPost("/oidc/token", test.codeForm(code, "verifier"), registered)
	request.Host = "sesame.test"
	request.Header.Set("DPoP", test.proof(key, "https://sesame.test/oidc/token"))

	response, err := test.controller(engine).PostToken(request)

	Assert.IsTrue(err == nil)
	Assert.Equals(http.StatusBadRequest, response.StatusCode)
	Assert.IsTrue(test.object(response)["access_token"] == nil)
}

func (test *StandardsControllerTest) TestBusyEngineIsReportedToTheErrorHandler() {
	setup := SesameTestSetup{}.Provision()
	defer setup.Remove()
	holder := setup.Open()
	defer holder.Close()
	setup.UseWait(200)
	engine := setup.Engine()

	response, err := test.controller(engine).GetJwks(test.get("/oidc/jwks"))

	var busy *host.EngineBusyError
	Assert.IsTrue(response == nil)
	Assert.IsTrue(errors.As(err, &busy))
}

func (test *StandardsControllerTest) register(engine *EngineHelper, tenantID string, audience string) sesame.ClientRegistration {
	registered := sesame.ClientRegistration{}
	SesameTestSetup{}.Check(engine.Call("oidc_client.register", map[string]any{
		"tenant_id": tenantID, "name": "Portal", "client_type": "confidential",
		"redirect_uris": []string{test.redirect()}, "scopes": []string{"openid", "offline_access"},
		"audience": audience, "post_logout_redirect_uris": []string{"https://rp.example/signed-out"},
	}, &registered))
	return registered
}

func (test *StandardsControllerTest) code(
	engine *EngineHelper,
	session sesame.IssuedSession,
	registered sesame.ClientRegistration,
) string {
	response, err := test.controller(engine).GetAuthorization(test.get(test.authorizeTarget(registered, test.challenge("verifier"))))
	SesameTestSetup{}.Check(err)
	identifier, secret, _ := strings.Cut(test.interactionCookie(response).Value, ":")
	completed := sesame.AuthorizationResponse{}
	SesameTestSetup{}.Check(engine.Call("oidc.interaction_complete", map[string]string{
		"interaction_id": identifier, "interaction_secret": secret,
		"session_id": session.SessionID, "session_secret": session.Secret,
	}, &completed))
	return completed.Code
}

func (test *StandardsControllerTest) tokens(
	engine *EngineHelper,
	session sesame.IssuedSession,
	registered sesame.ClientRegistration,
) map[string]any {
	code := test.code(engine, session, registered)
	response, err := test.controller(engine).PostToken(test.clientPost("/oidc/token", test.codeForm(code, "verifier"), registered))
	SesameTestSetup{}.Check(err)
	return test.object(response)
}

func (test *StandardsControllerTest) authorizeTarget(registered sesame.ClientRegistration, challenge string) string {
	query := url.Values{}
	query.Set("client_id", registered.Client.ID)
	query.Set("redirect_uri", test.redirect())
	query.Set("response_type", "code")
	query.Set("scope", "openid offline_access")
	query.Set("state", "state-value")
	query.Set("nonce", "nonce-value")
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	return "/oidc/authorize?" + query.Encode()
}

func (test *StandardsControllerTest) codeForm(code string, verifier string) string {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", test.redirect())
	form.Set("code_verifier", test.verifier(verifier))
	return form.Encode()
}

func (test *StandardsControllerTest) challenge(verifier string) string {
	digest := sha256.Sum256([]byte(test.verifier(verifier)))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (test *StandardsControllerTest) verifier(seed string) string {
	return seed + strings.Repeat("v", 43)
}

func (test *StandardsControllerTest) proof(key *ecdsa.PrivateKey, uri string) string {
	point, _ := key.PublicKey.Bytes()
	header := SesameTestSetup{}.Segment(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
			"y": base64.RawURLEncoding.EncodeToString(point[33:]),
		},
	})
	payload := SesameTestSetup{}.Segment(map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString([]byte(time.Now().String())),
		"htm": http.MethodPost, "htu": uri, "iat": time.Now().Unix(),
	})
	digest := sha256.Sum256([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	SesameTestSetup{}.Check(err)
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (test *StandardsControllerTest) interactionCookie(response *http.Response) *http.Cookie {
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Secure-sesame_interaction" {
			return cookie
		}
	}
	return &http.Cookie{}
}

func (test *StandardsControllerTest) redirect() string {
	return "https://rp.example/callback"
}

func (test *StandardsControllerTest) get(target string) *http.Request {
	return httptest.NewRequest(http.MethodGet, target, nil)
}

func (test *StandardsControllerTest) post(target string, form string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func (test *StandardsControllerTest) clientPost(target string, form string, registered sesame.ClientRegistration) *http.Request {
	request := test.post(target, form)
	request.SetBasicAuth(registered.Client.ID, registered.Secret)
	return request
}

func (test *StandardsControllerTest) text(response *http.Response) string {
	body, _ := io.ReadAll(response.Body)
	return string(body)
}

func (test *StandardsControllerTest) object(response *http.Response) map[string]any {
	decoded := map[string]any{}
	_ = json.Unmarshal([]byte(test.text(response)), &decoded)
	return decoded
}

func (test *StandardsControllerTest) controller(engine *EngineHelper) *StandardsController {
	return SesameTestSetup{}.Standards(engine)
}
