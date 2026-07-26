package adversarial_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/domain/saml/samltest"
)

// SAML attacks, driven through the shipped binary over the shipped machine
// protocol against a real deployment.
//
// The domain tests prove these refusals at a package boundary, and against
// libxml2 as an independent canonicalizer. These prove them where an attacker
// actually stands: on the far side of the protocol, against the engine an
// operator would deploy.

const (
	samlEntityID = "https://idp.adversarial.example/metadata"
	samlSSOURL   = "https://idp.adversarial.example/sso"
	samlConsumer = "https://app.example/saml/acs"
)

// samlDeployment is a deployment with one registered SAML provider plus the
// key that provider signs with.
type samlDeployment struct {
	*deployment
	signer     *samltest.Signer
	providerID string
}

func newSAMLDeployment(t *testing.T, linking string) *samlDeployment {
	t.Helper()

	deploy := newDeployment(t)
	signer, err := samltest.NewSigner("idp.adversarial.example")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	registered, err := deploy.client.SAMLProviderRegister(ctx, deploy.tenantID,
		"Hostile IdP", samlEntityID, samlSSOURL, []string{signer.PEM}, "email", linking)
	if err != nil {
		t.Fatalf("SAMLProviderRegister() error = %v", err)
	}
	providerID, _ := registered["provider_id"].(string)
	if providerID == "" {
		t.Fatalf("registration returned no provider id: %#v", registered)
	}
	return &samlDeployment{deployment: deploy, signer: signer, providerID: providerID}
}

// start opens a login and returns its id and the request id an assertion must
// answer.
func (d *samlDeployment) start(t *testing.T) (string, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	started, err := d.client.SAMLLoginStart(ctx, d.tenantID, d.providerID, samlConsumer)
	if err != nil {
		t.Fatalf("SAMLLoginStart() error = %v", err)
	}
	loginID, _ := started["login_id"].(string)
	requestID, _ := started["request_id"].(string)
	authnRequest, _ := started["authn_request"].(string)
	if loginID == "" || requestID == "" || authnRequest == "" {
		t.Fatalf("login start returned %#v", started)
	}
	if !strings.Contains(authnRequest, requestID) {
		t.Fatal("the AuthnRequest does not carry the ID an assertion must answer")
	}
	return loginID, requestID
}

// assertion builds a well-formed assertion for this deployment.
func (d *samlDeployment) assertion(requestID string) samltest.Assertion {
	now := time.Now().UTC()
	return samltest.Assertion{
		ID:           "_adversarial-" + requestID,
		Issuer:       samlEntityID,
		Subject:      "victim@example.com",
		Audience:     issuer,
		Recipient:    samlConsumer,
		RequestID:    requestID,
		NotBefore:    now.Add(-time.Minute),
		NotOnOrAfter: now.Add(5 * time.Minute),
	}
}

func (d *samlDeployment) sign(t *testing.T, assertion samltest.Assertion) string {
	t.Helper()

	document, err := d.signer.Sign(assertion.Document())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return document
}

// complete posts a raw document as the host would.
func (d *samlDeployment) complete(t *testing.T, loginID, document string) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err := d.client.SAMLLoginComplete(ctx, d.tenantID, loginID, samltest.Response(document))
	return err
}

// TestSAMLSignatureWrapping is the attack family this whole slice exists to
// stop: a genuine signature over a genuine assertion, carried alongside a
// forgery the reader is meant to pick up instead.
func TestSAMLSignatureWrapping(t *testing.T) {
	t.Parallel()

	deploy := newSAMLDeployment(t, "verified_email")

	cases := map[string]func(genuine string, requestID string) string{
		// Two assertions, one signed. The classic shape.
		"a forgery carried beside the signed assertion": func(genuine, _ string) string {
			forgery := strings.ReplaceAll(
				strings.Replace(genuine, `ID="_adversarial`, `ID="_forged`, 1),
				"victim@example.com", "attacker@example.com")
			// Strip the signature from the forgery so only the genuine one
			// carries it, which is precisely the wrapping shape.
			forgery = removeSignature(forgery)
			return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
				genuine + forgery + `</samlp:Response>`
		},
		// The same identifier on two elements, so the reference is ambiguous.
		"a duplicated element identifier": func(genuine, _ string) string {
			clone := removeSignature(strings.Replace(genuine,
				"victim@example.com", "attacker@example.com", 1))
			return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
				genuine + clone + `</samlp:Response>`
		},
		// Two signatures, so the verifier must choose which one counts.
		"a second signature": func(genuine, _ string) string {
			signature := extractSignature(genuine)
			return strings.Replace(genuine, signature, signature+signature, 1)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			loginID, requestID := deploy.start(t)
			genuine := deploy.sign(t, deploy.assertion(requestID))
			refused(t, "SAML wrapping with "+name,
				deploy.complete(t, loginID, build(genuine, requestID)),
				"saml_assertion_rejected")
		})
	}
}

// TestSAMLUnsignedAndTamperedAssertions covers the documents that carry no
// proof at all, and those whose proof no longer covers what they say.
func TestSAMLUnsignedAndTamperedAssertions(t *testing.T) {
	t.Parallel()

	deploy := newSAMLDeployment(t, "verified_email")

	cases := map[string]func(t *testing.T, genuine string) string{
		"no signature": func(_ *testing.T, genuine string) string {
			return removeSignature(genuine)
		},
		// The attack the digest exists to stop.
		"the subject rewritten after signing": func(_ *testing.T, genuine string) string {
			return strings.Replace(genuine, "victim@example.com", "attacker@example.com", 1)
		},
		// An assertion that never expires makes one capture permanent.
		"the validity window extended": func(_ *testing.T, genuine string) string {
			return strings.Replace(genuine, "NotOnOrAfter=\"20", "NotOnOrAfter=\"21", 1)
		},
		// Signed by a key this tenant never registered.
		"another key's signature": func(t *testing.T, genuine string) string {
			attacker, err := samltest.NewSigner("attacker.example")
			if err != nil {
				t.Fatalf("NewSigner() error = %v", err)
			}
			forged, err := attacker.Sign(removeSignature(genuine))
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			return forged
		},
		// SHA-1 is broken for this purpose and is not on the allowlist.
		"a SHA-1 downgrade": func(_ *testing.T, genuine string) string {
			return strings.NewReplacer(
				"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
				"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				"http://www.w3.org/2001/04/xmlenc#sha256",
				"http://www.w3.org/2000/09/xmldsig#sha1",
			).Replace(genuine)
		},
		// An HMAC over a published certificate would let anyone sign.
		"an HMAC downgrade": func(_ *testing.T, genuine string) string {
			return strings.Replace(genuine,
				"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
				"http://www.w3.org/2000/09/xmldsig#hmac-sha1", 1)
		},
		// A DOCTYPE is the door to entity expansion and external entities.
		"a DOCTYPE declaration": func(_ *testing.T, genuine string) string {
			return `<!DOCTYPE Assertion [<!ENTITY x "y">]>` + genuine
		},
		// Canonicalization SESAME does not implement must be refused, not
		// approximated.
		"inclusive canonicalization": func(_ *testing.T, genuine string) string {
			return strings.Replace(genuine, "http://www.w3.org/2001/10/xml-exc-c14n#",
				"http://www.w3.org/TR/2001/REC-xml-c14n-20010315", 1)
		},
		// Without the enveloped-signature transform the declared digest
		// cannot describe what was signed.
		"no enveloped-signature transform": func(_ *testing.T, genuine string) string {
			return strings.Replace(genuine,
				`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#`+
					`enveloped-signature"></ds:Transform>`, "", 1)
		},
		// An empty reference URI makes the signed scope depend on where the
		// reader stops rather than on an identifier both sides agree about.
		"a reference over the whole document": func(_ *testing.T, genuine string) string {
			return strings.Replace(genuine, `URI="#_adversarial`, `URI="`, 1)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			loginID, requestID := deploy.start(t)
			genuine := deploy.sign(t, deploy.assertion(requestID))
			attack := build(t, genuine)
			if attack == genuine {
				t.Fatal("the test did not alter the document")
			}
			refused(t, "SAML "+name, deploy.complete(t, loginID, attack),
				"saml_assertion_rejected")
		})
	}
}

// TestSAMLAssertionAnsweringTheWrongThing covers what a valid signature leaves
// open: who the assertion was written for, and which login it answers.
func TestSAMLAssertionAnsweringTheWrongThing(t *testing.T) {
	t.Parallel()

	deploy := newSAMLDeployment(t, "verified_email")

	cases := map[string]func(*samltest.Assertion){
		// Correctly signed by a provider SESAME does not know.
		"another provider's issuer": func(a *samltest.Assertion) {
			a.Issuer = "https://other.example/metadata"
		},
		// Without this, an assertion captured at any other service provider
		// the same identity provider serves would replay here.
		"another service provider's audience": func(a *samltest.Assertion) {
			a.Audience = "https://other.example/sp"
		},
		"another endpoint's recipient": func(a *samltest.Assertion) {
			a.Recipient = "https://evil.example/acs"
		},
		// An unsolicited assertion has no binding to a request SESAME sent.
		"no InResponseTo at all": func(a *samltest.Assertion) { a.RequestID = "" },
		"somebody else's login":  func(a *samltest.Assertion) { a.RequestID = "_another-login" },
		"an expired window": func(a *samltest.Assertion) {
			a.NotBefore = time.Now().Add(-2 * time.Hour)
			a.NotOnOrAfter = time.Now().Add(-time.Hour)
		},
		"a window that has not opened": func(a *samltest.Assertion) {
			a.NotBefore = time.Now().Add(time.Hour)
			a.NotOnOrAfter = time.Now().Add(2 * time.Hour)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			loginID, requestID := deploy.start(t)
			assertion := deploy.assertion(requestID)
			mutate(&assertion)
			refused(t, "SAML assertion with "+name,
				deploy.complete(t, loginID, deploy.sign(t, assertion)),
				"saml_assertion_rejected")
		})
	}
}

// TestSAMLAssertionReplay proves an assertion is worth nothing twice, against
// its own spent login and against a fresh one.
func TestSAMLAssertionReplay(t *testing.T) {
	t.Parallel()

	deploy := newSAMLDeployment(t, "verified_email")
	first, firstRequest := deploy.start(t)
	assertion := deploy.assertion(firstRequest)
	if err := deploy.complete(t, first, deploy.sign(t, assertion)); err != nil {
		t.Fatalf("the genuine login failed: %v", err)
	}

	// Against the spent transaction.
	refused(t, "SAML replay against a spent login",
		deploy.complete(t, first, deploy.sign(t, assertion)), "saml_login_not_found")

	// And against a fresh one, rewritten to answer it. The signature is
	// genuine and every condition holds; only the single-use claim stops it.
	second, secondRequest := deploy.start(t)
	replayed := assertion
	replayed.RequestID = secondRequest
	refused(t, "SAML replay against a fresh login",
		deploy.complete(t, second, deploy.sign(t, replayed)), "saml_assertion_rejected")
}

// TestSAMLCrossTenantSubstitution: a login belongs to the tenant that started
// it, and no other tenant may complete, read, or disable it.
func TestSAMLCrossTenantSubstitution(t *testing.T) {
	t.Parallel()

	deploy := newSAMLDeployment(t, "verified_email")
	loginID, requestID := deploy.start(t)
	document := deploy.sign(t, deploy.assertion(requestID))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	other, err := deploy.client.TenantBootstrap(ctx, "other-tenant")
	if err != nil {
		t.Fatalf("TenantBootstrap() error = %v", err)
	}
	otherID := other.Tenant.ID

	if _, err := deploy.client.SAMLLoginComplete(ctx, otherID, loginID,
		samltest.Response(document)); err == nil {
		t.Fatal("another tenant completed this tenant's SAML login")
	} else {
		refused(t, "SAML cross-tenant completion", err, "saml_login_not_found")
	}
	if _, err := deploy.client.SAMLProviderGet(ctx, otherID, deploy.providerID); err == nil {
		t.Fatal("another tenant read this tenant's SAML provider")
	} else {
		refused(t, "SAML cross-tenant read", err, "saml_provider_not_found")
	}
	if _, err := deploy.client.SAMLProviderDisable(ctx, otherID, deploy.providerID,
		"hostile"); err == nil {
		t.Fatal("another tenant disabled this tenant's SAML provider")
	} else {
		refused(t, "SAML cross-tenant disable", err, "saml_provider_not_found")
	}

	// The original login is still usable, which proves the refusals above
	// were isolation and not collateral damage.
	if err := deploy.complete(t, loginID, document); err != nil {
		t.Fatalf("the genuine login failed after the cross-tenant attempts: %v", err)
	}
}

// TestSAMLStrictLinkingRefusesAccountCreation: under strict linking a valid
// assertion for an unknown subject is not an authorization to create one.
func TestSAMLStrictLinkingRefusesAccountCreation(t *testing.T) {
	t.Parallel()

	deploy := newSAMLDeployment(t, "strict")
	loginID, requestID := deploy.start(t)
	refused(t, "SAML account creation under strict linking",
		deploy.complete(t, loginID, deploy.sign(t, deploy.assertion(requestID))),
		"saml_subject_not_linked")
}

// TestSAMLDisabledProviderStopsImmediately: disablement is the operator's
// emergency brake, so it must bite on the next request, not the next restart.
func TestSAMLDisabledProviderStopsImmediately(t *testing.T) {
	t.Parallel()

	deploy := newSAMLDeployment(t, "verified_email")
	loginID, requestID := deploy.start(t)
	document := deploy.sign(t, deploy.assertion(requestID))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if _, err := deploy.client.SAMLProviderDisable(ctx, deploy.tenantID,
		deploy.providerID, "compromised"); err != nil {
		t.Fatalf("SAMLProviderDisable() error = %v", err)
	}
	// An in-flight login must not survive its provider being disabled.
	refused(t, "SAML completion through a disabled provider",
		deploy.complete(t, loginID, document), "saml_provider_not_found")

	if _, err := deploy.client.SAMLLoginStart(ctx, deploy.tenantID, deploy.providerID,
		samlConsumer); err == nil {
		t.Fatal("a disabled provider started a login")
	} else {
		refused(t, "SAML login start through a disabled provider", err,
			"saml_provider_not_found")
	}
}

// removeSignature excises the ds:Signature element.
func removeSignature(document string) string {
	signature := extractSignature(document)
	if signature == "" {
		return document
	}
	return strings.Replace(document, signature, "", 1)
}

func extractSignature(document string) string {
	start := strings.Index(document, "<ds:Signature ")
	if start < 0 {
		return ""
	}
	const closing = "</ds:Signature>"
	end := strings.Index(document[start:], closing)
	if end < 0 {
		return ""
	}
	return document[start : start+end+len(closing)]
}
