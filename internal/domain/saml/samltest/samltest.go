// Package samltest builds genuinely signed SAML assertions for tests.
//
// It is test support and is imported only by _test.go files, so it never
// reaches a released binary.
//
// It signs without any canonicalizer of its own. Every document it emits is
// written already in exclusive-canonical form — attributes sorted, no unused
// namespace declarations, empty elements written with a closing tag — so its
// canonical form is byte-identical to its source and a plain SHA-256 over the
// raw bytes is the correct digest. That keeps the helper honest: it cannot
// paper over a canonicalization bug by using the same code the verifier does,
// and it needs no external tool, so tests using it never silently skip.
//
// The independent proof that SESAME's canonicalizer agrees with a real
// implementation lives in the saml package's libxml2 differential tests.
package samltest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Namespaces and algorithm identifiers, spelled here so a test reads as the
// wire does.
const (
	assertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	protocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	statusSuccess      = "urn:oasis:names:tc:SAML:2.0:status:Success"
	responseID         = "_response-envelope"
	signatureNamespace = "http://www.w3.org/2000/09/xmldsig#"
	bearerConfirmation = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

// Signer is an identity provider's signing key and certificate.
type Signer struct {
	key         *rsa.PrivateKey
	Certificate *x509.Certificate
	// PEM is the certificate as an operator would register it.
	PEM string
}

// NewSigner mints a self-signed provider certificate.
func NewSigner(commonName string) (*Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return &Signer{
		key:         key,
		Certificate: certificate,
		PEM:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}, nil
}

// Assertion is what a test wants to vary about an assertion.
type Assertion struct {
	ID           string
	Issuer       string
	Subject      string
	Audience     string
	Recipient    string
	RequestID    string
	NotBefore    time.Time
	NotOnOrAfter time.Time
}

// Document renders the assertion unsigned, in canonical form.
func (a Assertion) Document() string {
	return `<saml:Assertion xmlns:saml="` + assertionNamespace + `" ID="` + a.ID +
		`" IssueInstant="` + a.NotBefore.UTC().Format(time.RFC3339) + `" Version="2.0">` +
		`<saml:Issuer>` + a.Issuer + `</saml:Issuer>` +
		`<saml:Subject><saml:NameID>` + a.Subject + `</saml:NameID>` +
		`<saml:SubjectConfirmation Method="` + bearerConfirmation + `">` +
		`<saml:SubjectConfirmationData InResponseTo="` + a.RequestID +
		`" Recipient="` + a.Recipient + `"></saml:SubjectConfirmationData>` +
		`</saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotBefore="` + a.NotBefore.UTC().Format(time.RFC3339) +
		`" NotOnOrAfter="` + a.NotOnOrAfter.UTC().Format(time.RFC3339) + `">` +
		`<saml:AudienceRestriction><saml:Audience>` + a.Audience +
		`</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`</saml:Assertion>`
}

// InheritedDocument renders the assertion the way a real provider does: with
// the `saml` prefix used but never declared on the assertion itself.
//
// Every fixture in this package used to declare the prefix on the assertion
// element, which made the extracted subtree a standalone document by accident.
// Real providers — Keycloak among them — bind the prefix once on the enclosing
// Response, so the signed range refers to a prefix nothing inside it declares.
// A verifier that never sees this shape passes its own suite and fails on the
// first assertion anyone actually sends it. Pair with EnvelopeInResponse.
func (a Assertion) InheritedDocument() string {
	return strings.Replace(a.Document(),
		`<saml:Assertion xmlns:saml="`+assertionNamespace+`" `,
		`<saml:Assertion `, 1)
}

// EnvelopeInResponse wraps a signed assertion in the Response that carries its
// namespace binding, as the HTTP-POST binding delivers it.
func EnvelopeInResponse(signedAssertion string) string {
	return `<samlp:Response xmlns:samlp="` + protocolNamespace + `" xmlns:saml="` +
		assertionNamespace + `" ID="` + responseID + `" Version="2.0">` +
		`<samlp:Status><samlp:StatusCode Value="` + statusSuccess + `"></samlp:StatusCode>` +
		`</samlp:Status>` + signedAssertion + `</samlp:Response>`
}

// Sign envelopes a signature into an already-canonical document.
//
// The signature element is inserted whole, which leaves every other byte
// untouched — that is what makes the enveloped-signature excision reproduce
// exactly the bytes that were digested.
func (s *Signer) Sign(unsigned string) (string, error) {
	return s.sign(unsigned, unsigned)
}

// sign digests `canonical` and envelopes the signature into `emitted`.
//
// The two are the same document for a self-declaring assertion, and they
// differ for one that inherits its namespace: exclusive canonicalization adds
// the inherited binding back before digesting, so what is signed carries a
// declaration that what is sent does not.
func (s *Signer) sign(canonical, emitted string) (string, error) {
	digest := sha256.Sum256([]byte(canonical))
	reference := referenceID(canonical)
	signedInfo := `<ds:SignedInfo xmlns:ds="` + signatureNamespace + `">` +
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">` +
		`</ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256">` +
		`</ds:SignatureMethod>` +
		`<ds:Reference URI="#` + reference + `">` +
		`<ds:Transforms><ds:Transform Algorithm="` + signatureNamespace +
		`enveloped-signature"></ds:Transform></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256">` +
		`</ds:DigestMethod>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) +
		`</ds:DigestValue></ds:Reference></ds:SignedInfo>`

	signedInfoDigest := sha256.Sum256([]byte(signedInfo))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, signedInfoDigest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	element := `<ds:Signature xmlns:ds="` + signatureNamespace + `">` + signedInfo +
		`<ds:SignatureValue>` + base64.StdEncoding.EncodeToString(signature) +
		`</ds:SignatureValue></ds:Signature>`

	insertAt := strings.Index(emitted, "</saml:Issuer>")
	if insertAt < 0 {
		return "", fmt.Errorf("the document has no Issuer to sign after")
	}
	insertAt += len("</saml:Issuer>")
	return emitted[:insertAt] + element + emitted[insertAt:], nil
}

// SignInherited signs an assertion that leaves its namespace binding to the
// enclosing Response, the way a real provider emits one.
func (s *Signer) SignInherited(assertion Assertion) (string, error) {
	return s.sign(assertion.Document(), assertion.InheritedDocument())
}

// referenceID reads the root element's ID attribute.
func referenceID(document string) string {
	const marker = ` ID="`
	start := strings.Index(document, marker)
	if start < 0 {
		return ""
	}
	rest := document[start+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// Response base64-encodes a document as the HTTP-POST binding delivers it.
func Response(document string) string {
	return base64.StdEncoding.EncodeToString([]byte(document))
}

// SignedResponse is the whole path in one call: render, sign, encode.
func (s *Signer) SignedResponse(assertion Assertion) (string, error) {
	document, err := s.Sign(assertion.Document())
	if err != nil {
		return "", err
	}
	return Response(document), nil
}
