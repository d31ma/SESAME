package saml

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Differential validation of the canonicalizer against libxml2.
//
// The property tests in saml_test.go check rules SESAME believes in. They
// cannot establish that the canonical output is *correct*, because a signer
// built on this canonicalizer would agree with it whether or not it is — that
// circularity is the reason SAML support was not claimed on property tests
// alone.
//
// `xmllint --exc-c14n` is an independent implementation of the same
// specification, written by people who were not looking at this code. Where
// the two disagree, this code is wrong.
//
// The test skips when xmllint is absent rather than passing quietly, so a
// machine without it reports "not validated" instead of "validated".

func xmllintPath(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("xmllint")
	if err != nil {
		t.Skip("xmllint is not installed; the canonicalizer is unvalidated on this machine")
	}
	return path
}

// referenceCanonical runs libxml2's exclusive canonicalization.
//
// xmllint's --exc-c14n retains comments, so it is compared against
// withComments = true.
func referenceCanonical(t *testing.T, document string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "input.xml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	output, err := exec.Command(xmllintPath(t), "--exc-c14n", path).Output()
	if err != nil {
		t.Fatalf("xmllint --exc-c14n: %v", err)
	}
	return string(output)
}

// TestCanonicalMatchesLibxml2 is the validation the package doc calls for.
//
// Each case targets a rule that is easy to get wrong and whose failure mode
// is a signature that never verifies — or, worse, one that verifies over the
// wrong bytes.
func TestCanonicalMatchesLibxml2(t *testing.T) {
	t.Parallel()
	xmllintPath(t)

	cases := map[string]string{
		"attribute ordering": `<a:root xmlns:a="urn:a" xmlns:b="urn:b" z="26" a="1" b:m="13"/>`,

		// The defining property of *exclusive* canonicalization: a
		// declaration nothing uses is not rendered, which is what lets a
		// signed subtree survive being moved between documents.
		"unused namespace dropped": `<a:root xmlns:a="urn:a" xmlns:unused="urn:unused"/>`,

		// A binding an ancestor already rendered must not be repeated.
		"inherited namespace not repeated": `<a:root xmlns:a="urn:a"><a:child/></a:root>`,

		// A descendant that rebinds the same prefix to a different URI must
		// render it again.
		"rebound prefix": `<a:root xmlns:a="urn:a"><a:child xmlns:a="urn:other"/></a:root>`,

		"default namespace":         `<root xmlns="urn:d"><child/></root>`,
		"default namespace unset":   `<root xmlns="urn:d"><child xmlns=""/></root>`,
		"empty element expansion":   `<root/>`,
		"text escaping":             `<r>a &lt; b &amp; c &gt; d</r>`,
		"attribute escaping":        `<r a="q&quot;q&#x9;t&#xA;n"/>`,
		"carriage return in text":   "<r>line&#xD;break</r>",
		"comment retained":          `<r><!-- note --></r>`,
		"nested mixed content":      `<a:r xmlns:a="urn:a">before<a:c b="1">inner</a:c>after</a:r>`,
		"namespaced attribute only": `<r xmlns:x="urn:x" x:a="1"/>`,
		"whitespace preserved":      "<r>  spaced  </r>",
		"multiple children":         `<a:r xmlns:a="urn:a"><a:c/><a:c/><a:c/></a:r>`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want := referenceCanonical(t, document)
			got, err := canonicalizeBytes([]byte(document), true, nil)
			if err != nil {
				t.Fatalf("canonicalizeBytes() error = %v", err)
			}
			if string(got) != want {
				t.Errorf("canonical form differs from libxml2\n input: %s\n  ours: %s\n theirs: %s",
					document, got, want)
			}
		})
	}
}

// TestCanonicalMatchesLibxml2OnSAMLShapes runs the same comparison over the
// element shapes a real assertion carries, where a divergence would be a
// signature failure against every identity provider.
func TestCanonicalMatchesLibxml2OnSAMLShapes(t *testing.T) {
	t.Parallel()
	xmllintPath(t)

	cases := map[string]string{
		"assertion": `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
			`ID="_a1" IssueInstant="2026-01-01T00:00:00Z" Version="2.0">` +
			`<saml:Issuer>https://idp.example</saml:Issuer>` +
			`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` +
			`alice@example.com</saml:NameID></saml:Subject>` +
			`</saml:Assertion>`,

		// A response wrapping an assertion, with two prefixes in play.
		"response with assertion": `<samlp:Response ` +
			`xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
			`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">` +
			`<saml:Assertion ID="_a1"><saml:Issuer>i</saml:Issuer></saml:Assertion>` +
			`</samlp:Response>`,

		// SignedInfo is canonicalized separately from the assertion, and it
		// carries attributes on nested elements.
		"signed info": `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
			`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
			`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
			`<ds:Reference URI="#_a1"><ds:DigestValue>AA==</ds:DigestValue></ds:Reference>` +
			`</ds:SignedInfo>`,

		// Attribute statements carry xsi:type, which puts a third namespace
		// on an attribute rather than an element.
		"attribute statement": `<saml:AttributeStatement ` +
			`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
			`xmlns:xs="http://www.w3.org/2001/XMLSchema" ` +
			`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">` +
			`<saml:Attribute Name="groups">` +
			`<saml:AttributeValue xsi:type="xs:string">engineering</saml:AttributeValue>` +
			`</saml:Attribute></saml:AttributeStatement>`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want := referenceCanonical(t, document)
			got, err := canonicalizeBytes([]byte(document), true, nil)
			if err != nil {
				t.Fatalf("canonicalizeBytes() error = %v", err)
			}
			if string(got) != want {
				t.Errorf("canonical form differs from libxml2\n  ours: %s\n theirs: %s", got, want)
			}
		})
	}
}
