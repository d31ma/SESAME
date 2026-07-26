package saml

import (
	"encoding/xml"
	"errors"
	"strings"
	"testing"
)

// The structural tests below are deliberately independent of whether
// canonicalization is byte-correct. They assert what `locate` refuses, and a
// refusal happens before any digest is computed — so they stay meaningful
// even while the canonicalizer is still being validated against reference
// vectors.

const (
	assertionNS = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`
	dsigNS      = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
)

// signatureXML renders a Signature element referencing the given identifier.
func signatureXML(reference string) string {
	return `<ds:Signature ` + dsigNS + `>` +
		`<ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
		`<ds:Reference URI="#` + reference + `">` +
		`<ds:Transforms>` +
		`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
		`</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
		`<ds:DigestValue>AAAA</ds:DigestValue>` +
		`</ds:Reference>` +
		`</ds:SignedInfo>` +
		`<ds:SignatureValue>BBBB</ds:SignatureValue>` +
		`</ds:Signature>`
}

// assertion renders one assertion, optionally carrying a signature.
func assertion(id, subject, signature string) string {
	return `<saml:Assertion ` + assertionNS + ` ID="` + id + `">` +
		signature +
		`<saml:Subject><saml:NameID>` + subject + `</saml:NameID></saml:Subject>` +
		`</saml:Assertion>`
}

func TestLocateAcceptsASingleSignedAssertion(t *testing.T) {
	t.Parallel()

	document := []byte(assertion("a1", "alice", signatureXML("a1")))
	found, err := locate(document)
	if err != nil {
		t.Fatalf("locate() error = %v", err)
	}
	if found.Signed.ID != "a1" {
		t.Fatalf("signed element = %q, want a1", found.Signed.ID)
	}
	if found.Signed.Name.Space != namespaceAssertion || found.Signed.Name.Local != "Assertion" {
		t.Fatalf("signed element name = %#v", found.Signed.Name)
	}
	// The signature must sit inside the element it covers, or the excision
	// would remove bytes the signer never saw.
	if found.Signature.Start < found.Signed.Start || found.Signature.End > found.Signed.End {
		t.Fatal("the signature is not inside the element it references")
	}
}

// TestLocateRefusesSignatureWrapping is the reason this package exists.
//
// Every case below is a document an attacker can build from a legitimately
// signed assertion, and every one of them has broken a real SAML
// implementation. None is resolved cleverly; each is refused for being
// ambiguous about which element counts.
func TestLocateRefusesSignatureWrapping(t *testing.T) {
	t.Parallel()

	signed := assertion("a1", "alice", signatureXML("a1"))
	forged := assertion("a2", "attacker", "")

	cases := map[string]string{
		// The classic: keep the signed assertion, add a forged sibling. A
		// verifier that checks "is there a valid signature" and a reader that
		// takes "the first assertion" disagree.
		"two assertions, forgery second": `<samlp:Response ` +
			`xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` + signed + forged +
			`</samlp:Response>`,

		"two assertions, forgery first": `<samlp:Response ` +
			`xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` + forged + signed +
			`</samlp:Response>`,

		// Hide the signed original inside the forgery, so a reader walking
		// down finds the attacker's data first.
		"signed assertion nested inside a forgery": `<saml:Assertion ` + assertionNS +
			` ID="a2">` + signatureXML("a1") +
			`<saml:Subject><saml:NameID>attacker</saml:NameID></saml:Subject>` +
			signed + `</saml:Assertion>`,

		// Two signatures: which one is authoritative?
		"two signatures": `<saml:Assertion ` + assertionNS + ` ID="a1">` +
			signatureXML("a1") + signatureXML("a1") +
			`<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject>` +
			`</saml:Assertion>`,

		// The identifier the reference names appears twice, so "the element
		// with ID a1" is not a single element.
		"duplicate identifier": `<samlp:Response ` +
			`xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
			assertion("a1", "alice", signatureXML("a1")) +
			assertion("a1", "attacker", "") + `</samlp:Response>`,

		// A reference pointing at nothing: the signature covers no element in
		// this document, so there is nothing it authorises.
		"dangling reference": assertion("a1", "alice", signatureXML("nowhere")),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := locate([]byte(document)); err == nil {
				t.Fatal("locate accepted a wrapped document")
			} else if !errors.Is(err, ErrAmbiguous) {
				t.Fatalf("error = %v, want ErrAmbiguous", err)
			}
		})
	}
}

func TestLocateRefusesUnsignedAndMalformedDocuments(t *testing.T) {
	t.Parallel()

	t.Run("no signature", func(t *testing.T) {
		// An unsigned assertion is one anyone can write.
		if _, err := locate([]byte(assertion("a1", "alice", ""))); !errors.Is(err, ErrNoSignature) {
			t.Fatalf("error = %v, want ErrNoSignature", err)
		}
	})

	t.Run("doctype", func(t *testing.T) {
		document := `<!DOCTYPE r><r>` + assertion("a1", "alice", signatureXML("a1")) + `</r>`
		if _, err := locate([]byte(document)); !errors.Is(err, ErrDoctype) {
			t.Fatalf("error = %v, want ErrDoctype", err)
		}
	})

	t.Run("whole-document reference", func(t *testing.T) {
		// An empty reference URI means "everything", which makes the signed
		// scope depend on where the reader stops rather than on an identifier
		// both sides agree about.
		document := strings.Replace(assertion("a1", "alice", signatureXML("a1")),
			`URI="#a1"`, `URI=""`, 1)
		if _, err := locate([]byte(document)); !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("error = %v, want ErrAmbiguous", err)
		}
	})

	t.Run("no enveloped-signature transform", func(t *testing.T) {
		// Without it the digest would have to cover the signature itself.
		document := strings.Replace(assertion("a1", "alice", signatureXML("a1")),
			`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`,
			`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`, 1)
		if _, err := locate([]byte(document)); !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("error = %v, want ErrAmbiguous", err)
		}
	})
}

// TestLocateRefusesWeakAlgorithms covers the allowlist at the locate stage.
func TestLocateRefusesWeakAlgorithms(t *testing.T) {
	t.Parallel()

	t.Run("inclusive canonicalization", func(t *testing.T) {
		document := strings.Replace(assertion("a1", "alice", signatureXML("a1")),
			`Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"`,
			`Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"`, 1)
		if _, err := locate([]byte(document)); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("error = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
}

// TestSignatureAllowlistExcludesSHA1AndHMAC states the closed set directly.
// A SHA-1 signature is not evidence, and an HMAC method would let anyone
// holding the provider's published certificate mint assertions.
func TestSignatureAllowlistExcludesSHA1AndHMAC(t *testing.T) {
	t.Parallel()

	for _, forbidden := range []string{
		"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		"http://www.w3.org/2000/09/xmldsig#dsa-sha1",
		"http://www.w3.org/2000/09/xmldsig#hmac-sha1",
		"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
	} {
		if _, allowed := signatureAlgorithms[forbidden]; allowed {
			t.Fatalf("the allowlist admits %q", forbidden)
		}
	}
	for _, forbidden := range []string{
		"http://www.w3.org/2000/09/xmldsig#sha1",
	} {
		if _, allowed := digestAlgorithms[forbidden]; allowed {
			t.Fatalf("the digest allowlist admits %q", forbidden)
		}
	}
	if len(signatureAlgorithms) != 6 || len(digestAlgorithms) != 3 {
		t.Fatalf("the allowlists changed size: %d signature, %d digest",
			len(signatureAlgorithms), len(digestAlgorithms))
	}
}

// TestCanonicalOrdering covers the ordering rules a digest depends on. These
// are properties of the output, not conformance to a reference vector — see
// the package's outstanding-validation note.
func TestCanonicalOrdering(t *testing.T) {
	t.Parallel()

	document := []byte(`<a:root xmlns:a="urn:a" xmlns:b="urn:b" z="26" a="1" b:m="13"/>`)
	out, err := canonicalizeBytes(document, false, nil)
	if err != nil {
		t.Fatalf("canonicalizeBytes() error = %v", err)
	}
	rendered := string(out)

	// Unprefixed attributes sort before namespaced ones, and among
	// themselves by local name.
	if strings.Index(rendered, `a="1"`) > strings.Index(rendered, `z="26"`) {
		t.Fatalf("attributes are not sorted: %s", rendered)
	}
	// Only visibly used namespaces are rendered: urn:b is used by b:m, urn:a
	// by the element itself. Both appear.
	for _, want := range []string{`xmlns:a="urn:a"`, `xmlns:b="urn:b"`, `b:m="13"`} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("canonical form is missing %s: %s", want, rendered)
		}
	}
}

// TestCanonicalDropsUnusedNamespaces is the defining property of *exclusive*
// canonicalization: a declaration nothing uses is not rendered, which is what
// lets a signed subtree survive being moved between documents.
func TestCanonicalDropsUnusedNamespaces(t *testing.T) {
	t.Parallel()

	document := []byte(`<a:root xmlns:a="urn:a" xmlns:unused="urn:unused"/>`)
	out, err := canonicalizeBytes(document, false, nil)
	if err != nil {
		t.Fatalf("canonicalizeBytes() error = %v", err)
	}
	if strings.Contains(string(out), "urn:unused") {
		t.Fatalf("an unused namespace was rendered: %s", out)
	}
}

// TestCanonicalEscaping covers the escaping rules, which differ from Go's XML
// writer — using xml.EscapeText would produce a different digest.
func TestCanonicalEscaping(t *testing.T) {
	t.Parallel()

	document := []byte(`<r a="&quot;q&quot;&#x9;t">&lt;text&gt; &amp; more</r>`)
	out, err := canonicalizeBytes(document, false, nil)
	if err != nil {
		t.Fatalf("canonicalizeBytes() error = %v", err)
	}
	rendered := string(out)
	// A tab inside an attribute is escaped; inside text it is not.
	if !strings.Contains(rendered, "&#x9;") {
		t.Fatalf("a tab in an attribute was not escaped: %s", rendered)
	}
	// `>` is escaped in text, but a quote is not.
	if !strings.Contains(rendered, "&gt;") {
		t.Fatalf("a greater-than in text was not escaped: %s", rendered)
	}
}

// TestCanonicalRefusesDoctypeAndProcessingInstructions keeps the canonical
// surface as narrow as the locate surface.
func TestCanonicalRefusesDoctypeAndProcessingInstructions(t *testing.T) {
	t.Parallel()

	if _, err := canonicalizeBytes([]byte(`<?target data?><r/>`), false, nil); !errors.Is(
		err, ErrAmbiguous) {
		t.Fatalf("a processing instruction was canonicalized: %v", err)
	}
}

// TestInheritedNamespacesAreRendered covers the case a signed subtree depends
// on: a prefix declared by an ancestor outside the signed range must still be
// rendered, because it is visibly used and no longer in scope.
func TestInheritedNamespacesAreRendered(t *testing.T) {
	t.Parallel()

	out, err := canonicalizeBytes([]byte(`<a:child/>`), false,
		map[string]string{"a": "urn:inherited"})
	if err != nil {
		t.Fatalf("canonicalizeBytes() error = %v", err)
	}
	if !strings.Contains(string(out), `xmlns:a="urn:inherited"`) {
		t.Fatalf("an inherited namespace was not rendered: %s", out)
	}
}

// TestElementNameResolution confirms prefixes resolve to URIs, which is what
// lets locate tell a SAML Assertion from any other element called Assertion.
func TestElementNameResolution(t *testing.T) {
	t.Parallel()

	document := []byte(`<x:Assertion xmlns:x="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">` +
		signatureXML("a1") + `</x:Assertion>`)
	found, err := locate(document)
	if err != nil {
		t.Fatalf("locate() error = %v", err)
	}
	// A different prefix, the same namespace: still a SAML assertion.
	if found.Signed.Name != (xml.Name{
		Space: namespaceAssertion, Local: "Assertion",
	}) {
		t.Fatalf("resolved name = %#v", found.Signed.Name)
	}
}
