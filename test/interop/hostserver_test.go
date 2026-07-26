package interop_test

// The OpenID provider surface, exercised the way a relying party exercises it:
// over real HTTPS, through the host's own routes, with a browser's cookie jar.
//
// Everything else in this repository tests the engine. This tests the boundary
// the OpenID Foundation's conformance suite will drive — the HTTP edge that
// belongs to the host, where a wrong content type, a dropped cookie, or an
// endpoint advertised on the wrong origin breaks a flow the engine handled
// perfectly. Nothing here proves certification; it proves the target is worth
// pointing a certification suite at. See docs/CONFORMANCE.md.

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	hostPort     = "19443"
	hostIssuer   = "https://localhost:" + hostPort
	seedPassword = "correct horse battery staple"
	// redirectURI is the relying party this test plays. It never has to be
	// reachable: the browser stops at the redirect and the test reads the code
	// out of the Location header, exactly as the conformance suite does.
	redirectURI = "https://localhost:" + hostPort + "/callback"
)

// provider is a running hostserver and the credentials it seeded.
type provider struct {
	client       *http.Client
	tenantID     string
	principalID  string
	clientID     string
	clientSecret string
}

// startHostServer builds a deployment whose issuer is https, boots the example
// host over TLS, and waits for discovery to answer.
func startHostServer(t *testing.T) *provider {
	t.Helper()

	fylo := os.Getenv("FYLO_BINARY")
	if fylo == "" {
		t.Skip("set FYLO_BINARY to the pinned FYLO runtime")
	}
	workspace := t.TempDir()
	certificate := filepath.Join(workspace, "tls.crt")
	key := filepath.Join(workspace, "tls.key")
	generateCertificate(t, certificate, key)

	sesameBinary := buildSesame(t, workspace)
	deployment := filepath.Join(workspace, "deploy")
	// The issuer is https, which is what makes this a realistic target: the
	// engine composes every advertised endpoint under it and refuses any that
	// would leave the origin.
	initialise := exec.Command(sesameBinary, "init",
		"--deployment", deployment, "--fylo-binary", fylo, "--issuer", hostIssuer)
	if output, err := initialise.CombinedOutput(); err != nil {
		t.Fatalf("sesame init: %v\n%s", err, output)
	}

	command := exec.Command(sesameBinary+"-host",
		"--sesame", sesameBinary,
		"--deployment", deployment,
		"--addr", "127.0.0.1:"+hostPort,
		"--tls-cert", certificate,
		"--tls-key", key,
		"--seed-password", seedPassword,
		"--seed-client-redirects", redirectURI)
	command.Stderr = os.Stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the host server: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	var seeded struct {
		TenantID     string `json:"tenant_id"`
		PrincipalID  string `json:"principal_id"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(bufio.NewReader(stdout)).Decode(&seeded); err != nil {
		t.Fatalf("read the seeded credentials: %v", err)
	}

	instance := &provider{
		client:       browser(t),
		tenantID:     seeded.TenantID,
		principalID:  seeded.PrincipalID,
		clientID:     seeded.ClientID,
		clientSecret: seeded.ClientSecret,
	}
	waitForDiscovery(t, instance.client)
	return instance
}

// buildSesame compiles the engine and the example host for this platform.
func buildSesame(t *testing.T, workspace string) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("locate the repository root: %v", err)
	}
	engine := filepath.Join(workspace, "sesame")
	for target, output := range map[string]string{
		"./cmd/sesame":          engine,
		"./examples/hostserver": engine + "-host",
	} {
		build := exec.Command("go", "build", "-trimpath", "-o", output, target)
		build.Dir = root
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", target, err, out)
		}
	}
	return engine
}

func generateCertificate(t *testing.T, certificate, key string) {
	t.Helper()

	command := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-nodes", "-days", "3650", "-keyout", key, "-out", certificate,
		"-subj", "/CN=localhost",
		"-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate a TLS certificate: %v\n%s", err, output)
	}
}

// browser is an HTTP client that behaves like one: it keeps cookies and stops
// at the redirect so the test can read the authorization response.
func browser(t *testing.T) *http.Client {
	t.Helper()

	client := newInsecureClient(t)
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

func waitForDiscovery(t *testing.T, client *http.Client) {
	t.Helper()

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(hostIssuer + "/.well-known/openid-configuration")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	// A port already in use is the usual cause and is worth saying plainly.
	if listener, err := net.Listen("tcp", "127.0.0.1:"+hostPort); err == nil {
		_ = listener.Close()
		t.Fatal("the host server never served discovery, and the port is free — it failed to start")
	}
	t.Fatalf("the host server never served discovery; is port %s already in use?", hostPort)
}

// TestHostServerServesDiscoveryOverTLS. Everything the conformance suite does
// starts by reading this document, and every URL in it has to be an https URL
// on the issuer's own origin.
func TestHostServerServesDiscoveryOverTLS(t *testing.T) {
	skipUnlessEnabled(t)

	instance := startHostServer(t)
	response, err := instance.client.Get(hostIssuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer response.Body.Close()

	var metadata map[string]any
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if metadata["issuer"] != hostIssuer {
		t.Fatalf("issuer = %v, want %q", metadata["issuer"], hostIssuer)
	}
	for _, name := range []string{
		"authorization_endpoint", "token_endpoint", "jwks_uri",
		"introspection_endpoint", "revocation_endpoint", "end_session_endpoint",
	} {
		endpoint, _ := metadata[name].(string)
		if !strings.HasPrefix(endpoint, hostIssuer+"/") {
			t.Errorf("%s = %q, which is not on the issuer's origin", name, endpoint)
		}
	}
	// The JWKS has to be fetchable, or a relying party cannot verify anything.
	keys, err := instance.client.Get(hostIssuer + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer keys.Body.Close()
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(keys.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("the published key set is empty")
	}
	if jwks.Keys[0]["alg"] != "ES256" || jwks.Keys[0]["kid"] == "" {
		t.Fatalf("published key = %v", jwks.Keys[0])
	}
	// A published key set that leaked a private component would be the worst
	// possible bug on this surface, so it is asserted rather than assumed.
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		if _, present := jwks.Keys[0][private]; present {
			t.Fatalf("the published key carries the private member %q", private)
		}
	}
}

// TestHostServerRunsTheAuthorizationCodeFlow is the whole browser flow over
// TLS: authorize, log in, consent if asked, redeem, and verify the tokens.
func TestHostServerRunsTheAuthorizationCodeFlow(t *testing.T) {
	skipUnlessEnabled(t)

	instance := startHostServer(t)
	verifier := "sesame-conformance-verifier-0123456789-abcdefgh"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomValue(t)
	nonce := randomValue(t)

	code := instance.authorize(t, url.Values{
		"client_id":             {instance.clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})

	tokens := instance.redeem(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {instance.clientID},
		"client_secret": {instance.clientSecret},
		"code_verifier": {verifier},
	})
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("token response = %#v", tokens)
	}
	if tokens.TokenType != "Bearer" {
		t.Fatalf("token_type = %q", tokens.TokenType)
	}

	// The ID token has to name this issuer and this client, and carry the
	// nonce the request supplied — the three things a relying party checks.
	claims := decodeClaims(t, tokens.IDToken)
	if claims["iss"] != hostIssuer {
		t.Errorf("id_token iss = %v, want %q", claims["iss"], hostIssuer)
	}
	if claims["aud"] != instance.clientID {
		t.Errorf("id_token aud = %v, want %q", claims["aud"], instance.clientID)
	}
	if claims["nonce"] != nonce {
		t.Errorf("id_token nonce = %v, want %q", claims["nonce"], nonce)
	}

	// A code is single use. This is the one replay every conformance profile
	// checks, and it has to hold at the HTTP boundary and not only inside.
	replay := instance.post(t, hostIssuer+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {instance.clientID},
		"client_secret": {instance.clientSecret},
		"code_verifier": {verifier},
	})
	if replay.StatusCode < 400 {
		t.Fatalf("a redeemed code was accepted again with status %s", replay.Status)
	}
}

// TestHostServerRefusesAnUnregisteredRedirect. The authorization endpoint has
// to refuse before it shows anything, or an open redirect is one query
// parameter away.
func TestHostServerRefusesAnUnregisteredRedirect(t *testing.T) {
	skipUnlessEnabled(t)

	instance := startHostServer(t)
	sum := sha256.Sum256([]byte("sesame-conformance-verifier-0123456789-abcdefgh"))
	query := url.Values{
		"client_id":             {instance.clientID},
		"redirect_uri":          {"https://evil.example/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {randomValue(t)},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	response, err := instance.client.Get(hostIssuer + "/authorize?" + query.Encode())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 400 {
		t.Fatalf("an unregistered redirect URI was accepted with status %s", response.Status)
	}
	// And it must not bounce the browser at the attacker's URL to say so.
	if location := response.Header.Get("Location"); strings.Contains(location, "evil.example") {
		t.Fatalf("the refusal redirected to the attacker: %q", location)
	}
}

// authorize walks the browser half and returns the authorization code.
func (p *provider) authorize(t *testing.T, query url.Values) string {
	t.Helper()

	response, err := p.client.Get(hostIssuer + "/authorize?" + query.Encode())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	body := readBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authorize returned %s:\n%s", response.Status, truncate(body))
	}

	// Sign in. The host renders this page; the engine never sees a browser.
	login := p.post(t, hostIssuer+"/login", url.Values{
		"email":    {"admin@example.invalid"},
		"password": {seedPassword},
	})
	body = readBody(t, login)

	// A first-party client is not asked for consent, so the login may redirect
	// straight to the relying party. Follow whichever shape came back.
	for range 4 {
		location := login.Header.Get("Location")
		if location == "" {
			break
		}
		if strings.Contains(location, "code=") {
			return codeFrom(t, location)
		}
		next, err := p.client.Get(absolute(t, location))
		if err != nil {
			t.Fatalf("follow %s: %v", location, err)
		}
		body = readBody(t, next)
		login = next
	}
	if strings.Contains(body, `action="/consent"`) {
		consent := p.post(t, hostIssuer+"/consent", url.Values{"decision": {"allow"}})
		defer consent.Body.Close()
		if location := consent.Header.Get("Location"); strings.Contains(location, "code=") {
			return codeFrom(t, location)
		}
		t.Fatalf("consent produced no code; Location=%q", consent.Header.Get("Location"))
	}
	t.Fatalf("the login produced neither a code nor a consent page:\n%s", truncate(body))
	return ""
}

func (p *provider) redeem(t *testing.T, form url.Values) tokenResponse {
	t.Helper()

	response := p.post(t, hostIssuer+"/token", form)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("token returned %s", response.Status)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.Contains(contentType, "json") {
		t.Errorf("token Content-Type = %q, want JSON", contentType)
	}
	var tokens tokenResponse
	if err := json.NewDecoder(response.Body).Decode(&tokens); err != nil {
		t.Fatalf("decode the token response: %v", err)
	}
	return tokens
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

func (p *provider) post(t *testing.T, target string, form url.Values) *http.Response {
	t.Helper()

	response, err := p.client.PostForm(target, form)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	return response
}

func codeFrom(t *testing.T, location string) string {
	t.Helper()

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse the redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", location)
	}
	return code
}

func absolute(t *testing.T, location string) string {
	t.Helper()

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse %q: %v", location, err)
	}
	if parsed.IsAbs() {
		return location
	}
	base, _ := url.Parse(hostIssuer)
	return base.ResolveReference(parsed).String()
}

// decodeClaims reads a JWT's payload without verifying it. The signature is
// SESAME's own and is verified exhaustively elsewhere; what this checks is the
// claim wiring at the HTTP boundary.
func decodeClaims(t *testing.T, compact string) map[string]any {
	t.Helper()

	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		t.Fatalf("the ID token is not a compact JWS: %q", compact)
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatalf("decode the ID token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse the ID token payload: %v", err)
	}
	return claims
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the response body: %v", err)
	}
	return string(body)
}

func randomValue(t *testing.T) string {
	t.Helper()

	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("random: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func newInsecureClient(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return &http.Client{
		// The host serves a certificate it generated for itself. A real
		// deployment would carry one a relying party's trust store accepts —
		// which is the point of docs/CONFORMANCE.md and not something a test
		// on loopback can stand in for.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Jar:     jar,
		Timeout: 30 * time.Second,
	}
}
