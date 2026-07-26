package samltest_test

import (
	"strings"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/domain/saml"
	"github.com/d31ma/sesame/internal/domain/saml/samltest"
)

func fixture() samltest.Assertion {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	return samltest.Assertion{
		ID:           "_a1",
		Issuer:       "https://idp.example/metadata",
		Subject:      "alice@example.com",
		Audience:     "https://sesame.example",
		Recipient:    "https://app.example/acs",
		RequestID:    "_req1",
		NotBefore:    now.Add(-time.Minute),
		NotOnOrAfter: now.Add(5 * time.Minute),
	}
}

// TestSignedAssertionsVerify is the load-bearing claim of this package: that
// what it emits is already in exclusive-canonical form, so digesting the raw
// bytes is correct.
//
// Verify runs SESAME's real canonicalizer over the document, so a signature
// that checks out means canonicalize(document) == document byte for byte. It
// is not circular: the saml package separately proves its canonicalizer
// agrees with libxml2, so the chain ends at an independent implementation.
func TestSignedAssertionsVerify(t *testing.T) {
	t.Parallel()

	signer, err := samltest.NewSigner("idp.example")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	document, err := signer.Sign(fixture().Document())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	signed, err := saml.Verify([]byte(document), signer.Certificate)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if signed.ID != "_a1" {
		t.Fatalf("verified element ID = %q", signed.ID)
	}
	assertion, err := saml.ParseAssertion(signed)
	if err != nil {
		t.Fatalf("ParseAssertion() error = %v", err)
	}
	if err := assertion.Check(saml.Expectation{
		Issuer:    "https://idp.example/metadata",
		Audience:  "https://sesame.example",
		Recipient: "https://app.example/acs",
		RequestID: "_req1",
		Now:       time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

// TestTamperingBreaksTheSignature guards against the helper accidentally
// producing signatures that verify regardless of content — a signer that
// could do that would make every test using it vacuous.
func TestTamperingBreaksTheSignature(t *testing.T) {
	t.Parallel()

	signer, err := samltest.NewSigner("idp.example")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	document, err := signer.Sign(fixture().Document())
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	tampered := strings.Replace(document, "alice@example.com", "attacker@example.com", 1)
	if _, err := saml.Verify([]byte(tampered), signer.Certificate); err == nil {
		t.Fatal("a tampered assertion verified")
	}
}

// TestSignedResponseIsDecodable proves the base64 form matches what the
// engine expects from the HTTP-POST binding.
func TestSignedResponseIsDecodable(t *testing.T) {
	t.Parallel()

	signer, err := samltest.NewSigner("idp.example")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	response, err := signer.SignedResponse(fixture())
	if err != nil {
		t.Fatalf("SignedResponse() error = %v", err)
	}
	document, err := saml.DecodeResponse(response)
	if err != nil {
		t.Fatalf("DecodeResponse() error = %v", err)
	}
	if _, err := saml.Verify(document, signer.Certificate); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

// TestSignRequiresAnIssuerToEnvelopeAfter.
func TestSignRequiresAnIssuerToEnvelopeAfter(t *testing.T) {
	t.Parallel()

	signer, err := samltest.NewSigner("idp.example")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	if _, err := signer.Sign(`<saml:Assertion ID="_a1"></saml:Assertion>`); err == nil {
		t.Fatal("Sign accepted a document with no Issuer")
	}
}

// TestAssertionWithAnInheritedNamespaceParses is the regression test for the
// defect the Keycloak interoperability suite found.
//
// Verification always worked on this shape — the canonicalizer had the
// inherited bindings all along. Parsing did not: the signed byte range was
// handed to the XML decoder on its own, where `saml:` resolves to nothing, and
// the assertion came back unreadable. Every fixture here declared the prefix on
// the assertion itself, so the whole suite agreed with the bug.
//
// The shape below is Keycloak's: prefix used inside, bound on the Response.
func TestAssertionWithAnInheritedNamespaceParses(t *testing.T) {
	t.Parallel()

	signer, err := samltest.NewSigner("interop")
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	assertion := fixture()
	signed, err := signer.SignInherited(assertion)
	if err != nil {
		t.Fatalf("SignInherited() error = %v", err)
	}
	document := samltest.EnvelopeInResponse(signed)

	// The prefix really is only bound on the Response, or this proves nothing.
	inner := document[strings.Index(document, "<saml:Assertion"):]
	if strings.HasPrefix(inner, `<saml:Assertion xmlns:saml=`) {
		t.Fatal("the assertion declares its own namespace; this is the old shape")
	}

	verified, err := saml.Verify([]byte(document), signer.Certificate)
	if err != nil {
		t.Fatalf("Verify() on an inherited-namespace assertion: %v", err)
	}
	parsed, err := saml.ParseAssertion(verified)
	if err != nil {
		t.Fatalf("ParseAssertion() on an inherited-namespace assertion: %v", err)
	}
	if parsed.Subject != assertion.Subject {
		t.Fatalf("subject = %q, want %q", parsed.Subject, assertion.Subject)
	}
	if parsed.Issuer != assertion.Issuer {
		t.Fatalf("issuer = %q, want %q", parsed.Issuer, assertion.Issuer)
	}
}
