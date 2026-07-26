// Package interop_test runs SESAME's inbound protocol implementations against
// real identity providers.
//
// The adversarial suite proves SESAME refuses what it should. It cannot prove
// SESAME accepts what a real provider sends, because every document in it was
// written by SESAME's own test helpers — and a verifier and a forger that share
// an author agree by construction. This suite closes that gap: the assertions
// here are minted by Keycloak, signed by a key Keycloak generated, and carried
// through a browser flow that Keycloak drives.
//
// It is opt-in. Set SESAME_INTEROP=1 and have Docker running.
package interop_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	fyloadapter "github.com/d31ma/sesame/internal/adapters/fylo"
	"github.com/d31ma/sesame/internal/adapters/fylo/securityledger"
	identityapp "github.com/d31ma/sesame/internal/application/identity"
	authenticatordomain "github.com/d31ma/sesame/internal/domain/authenticator"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

const (
	// keycloakImage is pinned. An interoperability claim against "whatever
	// Keycloak was latest that week" is not a claim anyone can reproduce.
	keycloakImage = "quay.io/keycloak/keycloak:26.0"
	keycloakName  = "sesame-interop-keycloak"
	keycloakPort  = "18443"

	realm         = "sesame-interop"
	adminUser     = "admin"
	adminPass     = "admin"
	loginUser     = "alice"
	loginEmail    = "alice@interop.example"
	loginPassword = "correct horse battery staple"

	// issuer is SESAME's own entity ID, and therefore the Keycloak client ID:
	// a SAML client is named by the SP's entity ID.
	issuer      = "https://id.example.com"
	consumerURL = "http://127.0.0.1:19999/saml/acs"
)

func skipUnlessEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("SESAME_INTEROP") != "1" {
		t.Skip("set SESAME_INTEROP=1 (and have Docker running) for provider interoperability")
	}
}

// keycloak is a running instance and the details SESAME needs to trust it.
type keycloak struct {
	base        string
	adminToken  string
	client      *http.Client
	entityID    string
	ssoURL      string
	certificate string
}

// startKeycloak brings up a container, or reuses one an operator already
// started. Reuse matters during development: a full boot is ~20 seconds, and
// paying it on every run is how a suite stops being run.
func startKeycloak(t *testing.T) *keycloak {
	t.Helper()

	base := "https://localhost:" + keycloakPort
	transport := &http.Transport{
		// The container serves a certificate it generated for itself. This is
		// a test harness talking to a container on loopback, not a trust
		// decision SESAME makes: SESAME never speaks HTTP at all, and the
		// certificate that matters here is the SAML signing one, which is
		// verified properly.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 30 * time.Second}

	if !keycloakReady(client, base) {
		startKeycloakContainer(t)
		deadline := time.Now().Add(2 * time.Minute)
		for !keycloakReady(client, base) {
			if time.Now().After(deadline) {
				logs, _ := exec.Command("docker", "logs", "--tail", "40", keycloakName).CombinedOutput()
				t.Fatalf("Keycloak never became ready:\n%s", logs)
			}
			time.Sleep(time.Second)
		}
	}

	instance := &keycloak{base: base, client: client}
	instance.adminToken = instance.token(t)
	instance.configure(t)
	instance.readDescriptor(t)
	return instance
}

func keycloakReady(client *http.Client, base string) bool {
	response, err := client.Get(base + "/realms/master")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func startKeycloakContainer(t *testing.T) {
	t.Helper()

	certificates := t.TempDir()
	writeSelfSignedCertificate(t, certificates)
	_ = exec.Command("docker", "rm", "-f", keycloakName).Run()

	run := exec.Command("docker", "run", "-d", "--name", keycloakName,
		"-p", keycloakPort+":8443",
		"-e", "KC_BOOTSTRAP_ADMIN_USERNAME="+adminUser,
		"-e", "KC_BOOTSTRAP_ADMIN_PASSWORD="+adminPass,
		"-e", "KC_HTTPS_CERTIFICATE_FILE=/certs/tls.crt",
		"-e", "KC_HTTPS_CERTIFICATE_KEY_FILE=/certs/tls.key",
		"-v", certificates+":/certs:ro",
		keycloakImage, "start-dev")
	if output, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, output)
	}
	t.Cleanup(func() {
		if os.Getenv("SESAME_INTEROP_KEEP") == "1" {
			t.Logf("leaving %s running (SESAME_INTEROP_KEEP=1)", keycloakName)
			return
		}
		_ = exec.Command("docker", "rm", "-f", keycloakName).Run()
	})
}

// writeSelfSignedCertificate gives the container a TLS certificate.
//
// Keycloak will not serve HTTPS without one, and SESAME will not register a
// provider whose single sign-on URL is not https — which is the correct
// refusal, and the first thing this suite proved about real-world setup.
func writeSelfSignedCertificate(t *testing.T, directory string) {
	t.Helper()

	command := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-nodes", "-days", "3650",
		"-keyout", filepath.Join(directory, "tls.key"),
		"-out", filepath.Join(directory, "tls.crt"),
		"-subj", "/CN=localhost",
		"-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate a TLS certificate for Keycloak: %v\n%s", err, output)
	}
	for _, name := range []string{"tls.crt", "tls.key"} {
		// The container runs as a non-root user and has to read both.
		if err := os.Chmod(filepath.Join(directory, name), 0o644); err != nil {
			t.Fatalf("chmod %s: %v", name, err)
		}
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatalf("chmod certificate directory: %v", err)
	}
}

func (k *keycloak) token(t *testing.T) string {
	t.Helper()

	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {adminUser},
		"password":   {adminPass},
	}
	response, err := k.client.PostForm(
		k.base+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatalf("acquire an admin token: %v", err)
	}
	defer response.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode the admin token: %v", err)
	}
	if body.AccessToken == "" {
		t.Fatal("Keycloak returned no admin token")
	}
	return body.AccessToken
}

// admin issues one admin-API call, tolerating "already exists" so the suite is
// re-runnable against a kept container.
func (k *keycloak) admin(t *testing.T, method, path string, payload any) {
	t.Helper()

	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
	request, err := http.NewRequest(method, k.base+path, strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	request.Header.Set("Authorization", "Bearer "+k.adminToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := k.client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusCreated, http.StatusNoContent, http.StatusOK, http.StatusConflict:
		return
	default:
		t.Fatalf("%s %s: unexpected status %s", method, path, response.Status)
	}
}

// configure creates the realm, the SAML client naming SESAME, and a user.
func (k *keycloak) configure(t *testing.T) {
	t.Helper()

	k.admin(t, http.MethodPost, "/admin/realms", map[string]any{
		"realm": realm, "enabled": true,
	})
	k.admin(t, http.MethodPost, "/admin/realms/"+realm+"/clients", map[string]any{
		// A SAML client is named by the service provider's entity ID, which
		// for SESAME is its deployment issuer.
		"clientId":     issuer,
		"protocol":     "saml",
		"enabled":      true,
		"redirectUris": []string{"http://127.0.0.1:19999/*"},
		"attributes": map[string]string{
			// SESAME verifies the signature on the Assertion, not on the
			// Response. A provider configured to sign only the response
			// produces a document SESAME refuses — correctly, since an
			// unsigned assertion inside a signed envelope is the classic
			// wrapping shape.
			"saml.assertion.signature": "true",
			"saml.server.signature":    "false",
			// SESAME does not sign its AuthnRequests, so the provider must
			// not require it. This is a documented gap, not a defect.
			"saml.client.signature":            "false",
			"saml.signature.algorithm":         "RSA_SHA256",
			"saml_name_id_format":              "email",
			"saml_force_name_id_format":        "true",
			"saml_assertion_consumer_url_post": consumerURL,
		},
	})
	k.admin(t, http.MethodPost, "/admin/realms/"+realm+"/users", map[string]any{
		"username": loginUser, "email": loginEmail, "emailVerified": true,
		"firstName": "Alice", "lastName": "Interop", "enabled": true,
		"credentials": []map[string]any{
			{"type": "password", "value": loginPassword, "temporary": false},
		},
	})
}

// readDescriptor takes the provider's entity ID, SSO URL, and signing
// certificate from its published metadata, exactly as an operator would.
func (k *keycloak) readDescriptor(t *testing.T) {
	t.Helper()

	response, err := k.client.Get(k.base + "/realms/" + realm + "/protocol/saml/descriptor")
	if err != nil {
		t.Fatalf("fetch the SAML descriptor: %v", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the SAML descriptor: %v", err)
	}
	document := string(raw)

	entity := regexp.MustCompile(`entityID="([^"]+)"`).FindStringSubmatch(document)
	certificate := regexp.MustCompile(
		`(?s)<ds:X509Certificate>(.*?)</ds:X509Certificate>`).FindStringSubmatch(document)
	sso := regexp.MustCompile(
		`<md:SingleSignOnService Binding="[^"]*HTTP-Redirect" Location="([^"]+)"`).
		FindStringSubmatch(document)
	if entity == nil || certificate == nil || sso == nil {
		t.Fatalf("the descriptor is missing an entity ID, certificate, or SSO URL:\n%s", document)
	}
	k.entityID = entity[1]
	k.ssoURL = sso[1]
	k.certificate = strings.Join(strings.Fields(certificate[1]), "")
}

// login drives the browser half of the flow and returns the raw SAMLResponse.
//
// This is the part no unit test can stand in for: Keycloak renders a login
// page, takes a password, and answers with a self-submitting form carrying an
// assertion it signed.
func (k *keycloak) login(t *testing.T, redirectURL string) []byte {
	t.Helper()

	page := k.get(t, redirectURL)
	action, fields := parseForm(t, page, "SAML login page")
	fields.Set("username", loginUser)
	fields.Set("password", loginPassword)

	target, err := url.Parse(action)
	if err != nil {
		t.Fatalf("parse the login form action: %v", err)
	}
	if !target.IsAbs() {
		base, _ := url.Parse(k.base)
		target = base.ResolveReference(target)
	}

	response, err := k.client.PostForm(target.String(), fields)
	if err != nil {
		t.Fatalf("submit the login form: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read the login response: %v", err)
	}

	posted := regexp.MustCompile(
		`name="SAMLResponse"[^>]*value="([^"]*)"`).FindStringSubmatch(string(body))
	if posted == nil {
		t.Fatalf("no SAMLResponse in Keycloak's reply; the login probably failed:\n%s",
			truncate(string(body)))
	}
	decoded, err := base64.StdEncoding.DecodeString(html.UnescapeString(posted[1]))
	if err != nil {
		t.Fatalf("decode the SAMLResponse: %v", err)
	}
	if dump := os.Getenv("SESAME_INTEROP_DUMP"); dump != "" {
		if err := os.WriteFile(dump, decoded, 0o600); err != nil {
			t.Fatalf("dump the assertion: %v", err)
		}
		t.Logf("wrote the provider's assertion to %s", dump)
	}
	return decoded
}

func (k *keycloak) get(t *testing.T, target string) string {
	t.Helper()

	response, err := k.client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s: %v", target, err)
	}
	return string(body)
}

// parseForm pulls the action and hidden fields out of the first form on a page.
func parseForm(t *testing.T, page, what string) (string, url.Values) {
	t.Helper()

	form := regexp.MustCompile(`(?s)<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>`).
		FindStringSubmatch(page)
	if form == nil {
		t.Fatalf("no form on the %s:\n%s", what, truncate(page))
	}
	fields := url.Values{}
	inputs := regexp.MustCompile(`<input[^>]*>`).FindAllString(form[2], -1)
	for _, input := range inputs {
		name := regexp.MustCompile(`name="([^"]*)"`).FindStringSubmatch(input)
		value := regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(input)
		if name == nil {
			continue
		}
		if value != nil {
			fields.Set(name[1], html.UnescapeString(value[1]))
		}
	}
	return html.UnescapeString(form[1]), fields
}

func truncate(body string) string {
	if len(body) > 1500 {
		return body[:1500] + "\n… truncated"
	}
	return body
}

// sesameService opens a real FYLO-backed engine. Interoperability evidence
// against an in-memory stand-in would prove less than it appears to.
func sesameService(t *testing.T) (*identityapp.Service, context.Context) {
	t.Helper()

	binary := os.Getenv("FYLO_BINARY")
	if binary == "" {
		t.Skip("set FYLO_BINARY to the pinned FYLO runtime")
	}
	root := t.TempDir()
	config := fyloadapter.Config{
		Binary:                 binary,
		Root:                   filepath.Join(root, "db"),
		ExpectedRuntimeVersion: fyloadapter.PhaseOneRuntimeVersion,
		ExpectedBuildTarget:    os.Getenv("SESAME_FYLO_BUILD_TARGET"),
		AllowDevelopmentBuild:  os.Getenv("SESAME_FYLO_ALLOW_DEVELOPMENT") == "1",
	}
	if err := os.Mkdir(config.Root, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	client, err := fyloadapter.Start(ctx, config)
	if err != nil {
		t.Fatalf("start FYLO: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ledger, events, err := securityledger.Open(ctx, client)
	if err != nil {
		t.Fatalf("open the ledger: %v", err)
	}
	service, err := identityapp.New(ledger, events)
	if err != nil {
		t.Fatalf("identity.New(): %v", err)
	}
	secretsKey := make([]byte, authenticatordomain.SealedSecretKeyBytes)
	if _, err := rand.Read(secretsKey); err != nil {
		t.Fatalf("generate a secrets key: %v", err)
	}
	signing, err := tokendomain.NewSigningKey()
	if err != nil {
		t.Fatalf("NewSigningKey(): %v", err)
	}
	service.UseSecretsKey(secretsKey)
	service.UseSigningKey(signing)
	service.UseIssuer(issuer)
	return service, ctx
}

// TestKeycloakSAMLLoginInteroperates is the headline: a person authenticates at
// Keycloak and arrives at SESAME as a principal.
//
// Nothing in the assertion was written by this repository. Keycloak chose the
// XML layout, the namespace prefixes, the canonicalization, the digest, and the
// signature — and those choices are exactly what a hand-written fixture cannot
// vary, which is why a verifier can pass an adversarial suite and still fail
// against the first real provider it meets.
func TestKeycloakSAMLLoginInteroperates(t *testing.T) {
	skipUnlessEnabled(t)

	provider := startKeycloak(t)
	service, ctx := sesameService(t)

	tenant, err := service.Bootstrap(ctx, "interop", "test:interop")
	if err != nil {
		t.Fatalf("Bootstrap(): %v", err)
	}

	registered, err := service.SAMLProviderRegister(ctx, tenant.Tenant.ID, "keycloak",
		provider.entityID, provider.ssoURL, []string{provider.certificate},
		"email", "verified_email", "test:interop")
	if err != nil {
		t.Fatalf("SAMLProviderRegister() with Keycloak's own metadata: %v", err)
	}

	login, err := service.SAMLLoginStart(ctx, tenant.Tenant.ID, registered.ID,
		consumerURL, "test:interop")
	if err != nil {
		t.Fatalf("SAMLLoginStart(): %v", err)
	}
	if login.RedirectURL == "" {
		t.Fatal("SAMLLoginStart() produced no redirect URL")
	}

	// Keycloak has to accept SESAME's AuthnRequest before it will render a
	// login page, so reaching a form at all already proves the request
	// encoding, the binding, and the entity ID are right.
	assertion := provider.login(t, login.RedirectURL)
	if !strings.Contains(string(assertion), "Assertion") {
		t.Fatalf("Keycloak returned no assertion:\n%s", truncate(string(assertion)))
	}

	session, err := service.SAMLLoginComplete(ctx, tenant.Tenant.ID, login.LoginID,
		assertion, "test:interop")
	if err != nil {
		t.Fatalf("SAMLLoginComplete() on a Keycloak-signed assertion: %v", err)
	}
	if session.Session.SessionID == "" || session.Session.Secret == "" {
		t.Fatalf("the completed login issued no session: %#v", session)
	}
	if session.PrincipalID == "" {
		t.Fatal("the completed login bound no principal")
	}

	// The session is a real one: it verifies through the same rule every
	// other surface uses.
	verified, err := service.SessionVerify(session.Session.SessionID, session.Session.Secret)
	if err != nil {
		t.Fatalf("the session from a federated login does not verify: %v", err)
	}
	if verified.PrincipalID != session.PrincipalID {
		t.Fatalf("session verifies as %q, login reported %q",
			verified.PrincipalID, session.PrincipalID)
	}
	t.Logf("Keycloak %s: principal %s, session %s, provisioned=%v",
		keycloakImage, session.PrincipalID, session.Session.SessionID, session.Provisioned)
}

// TestKeycloakAssertionIsSingleUse. A real assertion is the one thing an
// attacker who watched a browser flow actually has, so replaying it is the
// attack that matters — and it has to be refused with a document SESAME did
// not write, not only with fixtures.
func TestKeycloakAssertionIsSingleUse(t *testing.T) {
	skipUnlessEnabled(t)

	provider := startKeycloak(t)
	service, ctx := sesameService(t)

	tenant, err := service.Bootstrap(ctx, "interop-replay", "test:interop")
	if err != nil {
		t.Fatalf("Bootstrap(): %v", err)
	}
	registered, err := service.SAMLProviderRegister(ctx, tenant.Tenant.ID, "keycloak",
		provider.entityID, provider.ssoURL, []string{provider.certificate},
		"email", "verified_email", "test:interop")
	if err != nil {
		t.Fatalf("SAMLProviderRegister(): %v", err)
	}
	login, err := service.SAMLLoginStart(ctx, tenant.Tenant.ID, registered.ID,
		consumerURL, "test:interop")
	if err != nil {
		t.Fatalf("SAMLLoginStart(): %v", err)
	}
	assertion := provider.login(t, login.RedirectURL)

	if _, err := service.SAMLLoginComplete(ctx, tenant.Tenant.ID, login.LoginID,
		assertion, "test:interop"); err != nil {
		t.Fatalf("SAMLLoginComplete(): %v", err)
	}
	if _, err := service.SAMLLoginComplete(ctx, tenant.Tenant.ID, login.LoginID,
		assertion, "test:interop"); err == nil {
		t.Fatal("a real Keycloak assertion was accepted twice")
	}
}

// TestKeycloakAssertionIsRefusedByAnotherTenant: a genuine, correctly signed
// assertion is still not a passport. Tenant isolation has to hold against a
// document that is valid in every other respect.
func TestKeycloakAssertionIsRefusedByAnotherTenant(t *testing.T) {
	skipUnlessEnabled(t)

	provider := startKeycloak(t)
	service, ctx := sesameService(t)

	victim, err := service.Bootstrap(ctx, "interop-victim", "test:interop")
	if err != nil {
		t.Fatalf("Bootstrap(): %v", err)
	}
	attacker, err := service.Bootstrap(ctx, "interop-attacker", "test:interop")
	if err != nil {
		t.Fatalf("Bootstrap(): %v", err)
	}
	registered, err := service.SAMLProviderRegister(ctx, victim.Tenant.ID, "keycloak",
		provider.entityID, provider.ssoURL, []string{provider.certificate},
		"email", "verified_email", "test:interop")
	if err != nil {
		t.Fatalf("SAMLProviderRegister(): %v", err)
	}
	login, err := service.SAMLLoginStart(ctx, victim.Tenant.ID, registered.ID,
		consumerURL, "test:interop")
	if err != nil {
		t.Fatalf("SAMLLoginStart(): %v", err)
	}
	assertion := provider.login(t, login.RedirectURL)

	if _, err := service.SAMLLoginComplete(ctx, attacker.Tenant.ID, login.LoginID,
		assertion, "test:interop"); err == nil {
		t.Fatal("another tenant completed a login it did not start")
	}
}

// TestKeycloakTamperedAssertionIsRefused. Keycloak's signature covers the
// assertion; editing any byte of it has to break verification. This is the
// same claim the adversarial suite makes, made once against a document with a
// real provider's canonicalization rather than SESAME's own.
func TestKeycloakTamperedAssertionIsRefused(t *testing.T) {
	skipUnlessEnabled(t)

	provider := startKeycloak(t)
	service, ctx := sesameService(t)

	tenant, err := service.Bootstrap(ctx, "interop-tamper", "test:interop")
	if err != nil {
		t.Fatalf("Bootstrap(): %v", err)
	}
	registered, err := service.SAMLProviderRegister(ctx, tenant.Tenant.ID, "keycloak",
		provider.entityID, provider.ssoURL, []string{provider.certificate},
		"email", "verified_email", "test:interop")
	if err != nil {
		t.Fatalf("SAMLProviderRegister(): %v", err)
	}
	login, err := service.SAMLLoginStart(ctx, tenant.Tenant.ID, registered.ID,
		consumerURL, "test:interop")
	if err != nil {
		t.Fatalf("SAMLLoginStart(): %v", err)
	}
	assertion := provider.login(t, login.RedirectURL)

	// Rewrite the subject to somebody else. This is the whole attack: a
	// stolen assertion, edited to name an administrator.
	tampered := strings.Replace(string(assertion), loginEmail, "root@interop.example", 1)
	if tampered == string(assertion) {
		t.Fatalf("the subject %q was not present to tamper with", loginEmail)
	}
	if _, err := service.SAMLLoginComplete(ctx, tenant.Tenant.ID, login.LoginID,
		[]byte(tampered), "test:interop"); err == nil {
		t.Fatal("an edited Keycloak assertion was accepted")
	}
}

// reportedImage keeps the pinned version visible in test output, so evidence
// gathered from a run names what it was gathered against.
func TestMain(m *testing.M) {
	if os.Getenv("SESAME_INTEROP") == "1" {
		fmt.Fprintf(os.Stderr, "interoperability provider: %s\n", keycloakImage)
	}
	os.Exit(m.Run())
}
