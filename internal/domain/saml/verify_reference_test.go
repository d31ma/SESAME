package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// End-to-end verification against a signature this package did not help
// produce.
//
// The digest and the SignedInfo are canonicalized by libxml2, not by SESAME,
// and only then signed. If SESAME's canonicalizer disagreed with libxml2's by
// a single byte, Verify would fail — which is the point. A test that signed
// using SESAME's own canonical output would pass whether or not that output
// is correct, and would prove nothing about interoperating with a real
// identity provider.

// testSigner is an identity provider's key and certificate.
type testSigner struct {
	key         *rsa.PrivateKey
	certificate *x509.Certificate
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &testSigner{key: key, certificate: certificate}
}

// sign builds a signed assertion, canonicalizing with xmllint throughout.
func (s *testSigner) sign(t *testing.T, unsigned string) string {
	t.Helper()
	return s.signWith(t, unsigned, referenceCanonical)
}

// signWith builds a signed assertion using the supplied canonicalizer.
func (s *testSigner) signWith(
	t *testing.T,
	unsigned string,
	canonical func(*testing.T, string) string,
) string {
	t.Helper()

	// 1. Digest the assertion as it stands, before any signature exists.
	//    This is what the enveloped-signature transform will reproduce.
	digest := sha256.Sum256([]byte(canonical(t, unsigned)))

	// 2. Build SignedInfo naming that digest.
	signedInfo := `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>` +
		`<ds:Reference URI="#_a1">` +
		`<ds:Transforms>` +
		`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>` +
		`</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(digest[:]) + `</ds:DigestValue>` +
		`</ds:Reference>` +
		`</ds:SignedInfo>`

	// 3. Sign its canonical form, again per libxml2.
	signedInfoDigest := sha256.Sum256([]byte(canonical(t, signedInfo)))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, signedInfoDigest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// 4. Envelope it. Inserting a complete element leaves the rest of the
	//    document byte-identical, which is what makes the excision in step 1
	//    reproducible.
	element := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` + signedInfo +
		`<ds:SignatureValue>` + base64.StdEncoding.EncodeToString(signature) +
		`</ds:SignatureValue></ds:Signature>`
	insertAt := strings.Index(unsigned, "<saml:Issuer>")
	if insertAt < 0 {
		t.Fatal("the unsigned assertion has no Issuer to insert after")
	}
	return unsigned[:insertAt] + element + unsigned[insertAt:]
}

func sesameCanonical(t *testing.T, document string) string {
	t.Helper()

	canonical, err := canonicalizeBytes([]byte(document), true, nil)
	if err != nil {
		t.Fatalf("canonicalize test document: %v", err)
	}
	return string(canonical)
}

func unsignedAssertion() string {
	return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">` +
		`<saml:Issuer>` + testIssuer + `</saml:Issuer>` +
		`<saml:Subject><saml:NameID>alice@example.com</saml:NameID>` +
		`<saml:SubjectConfirmation Method="` + BearerConfirmation + `">` +
		`<saml:SubjectConfirmationData InResponseTo="` + testRequestID +
		`" Recipient="` + testRecipient + `"></saml:SubjectConfirmationData>` +
		`</saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotBefore="2026-01-01T11:59:00Z" NotOnOrAfter="2026-01-01T12:05:00Z">` +
		`<saml:AudienceRestriction><saml:Audience>` + testAudience +
		`</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`</saml:Assertion>`
}

// TestVerifyMechanicsWithoutExternalTools keeps the verifier's deterministic
// mechanics covered on every CI runner. It deliberately uses SESAME's own
// canonicalizer, so it is not interoperability evidence; the libxml2 tests
// below remain the independent conformance proof.
func TestVerifyMechanicsWithoutExternalTools(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	document := signer.signWith(t, unsignedAssertion(), sesameCanonical)

	t.Run("accepts an intact assertion", func(t *testing.T) {
		signed, err := Verify([]byte(document), signer.certificate)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if signed.ID != "_a1" {
			t.Fatalf("verified element ID = %q", signed.ID)
		}
	})

	t.Run("refuses content tampering", func(t *testing.T) {
		tampered := strings.Replace(document, "alice@example.com", "attacker@example.com", 1)
		if _, err := Verify([]byte(tampered), signer.certificate); !errors.Is(
			err, ErrDigestMismatch) {
			t.Fatalf("Verify() error = %v, want ErrDigestMismatch", err)
		}
	})

	t.Run("refuses another key", func(t *testing.T) {
		other := newTestSigner(t)
		if _, err := Verify([]byte(document), other.certificate); !errors.Is(
			err, ErrSignatureInvalid) {
			t.Fatalf("Verify() error = %v, want ErrSignatureInvalid", err)
		}
	})

	t.Run("refuses wrapping", func(t *testing.T) {
		forgery := strings.Replace(
			strings.Replace(unsignedAssertion(), `ID="_a1"`, `ID="_a2"`, 1),
			"alice@example.com", "attacker@example.com", 1)
		wrapped := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
			document + forgery + `</samlp:Response>`
		if _, err := Verify([]byte(wrapped), signer.certificate); !errors.Is(
			err, ErrAmbiguous) {
			t.Fatalf("Verify() error = %v, want ErrAmbiguous", err)
		}
	})
}

// TestVerifyAcceptsALibxml2SignedAssertion is the end-to-end proof that
// SESAME's canonicalization agrees with an independent implementation closely
// enough for a signature to verify.
func TestVerifyAcceptsALibxml2SignedAssertion(t *testing.T) {
	t.Parallel()
	xmllintPath(t)

	signer := newTestSigner(t)
	document := signer.sign(t, unsignedAssertion())

	signed, err := Verify([]byte(document), signer.certificate)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if signed.ID != "_a1" {
		t.Fatalf("verified element ID = %q", signed.ID)
	}

	assertion, err := ParseAssertion(signed)
	if err != nil {
		t.Fatalf("ParseAssertion() error = %v", err)
	}
	if assertion.Subject != "alice@example.com" {
		t.Fatalf("subject = %q", assertion.Subject)
	}
	if err := assertion.Check(defaultExpectation()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

// TestVerifyRefusesTamperingWithASignedAssertion proves the digest actually
// covers the assertion's content, not merely its shape.
func TestVerifyRefusesTamperingWithASignedAssertion(t *testing.T) {
	t.Parallel()
	xmllintPath(t)

	signer := newTestSigner(t)
	document := signer.sign(t, unsignedAssertion())

	cases := map[string][2]string{
		// The attack this whole package exists to stop: change who the
		// assertion is about, leave the signature alone.
		"subject substitution": {"alice@example.com", "attacker@example.com"},
		// Extend the validity window so a captured assertion never expires.
		"window extension": {"2026-01-01T12:05:00Z", "2036-01-01T12:05:00Z"},
		// Redirect it to a different service provider.
		"audience substitution": {testAudience, "https://evil.example/sp"},
		// Point the delivery elsewhere.
		"recipient substitution": {testRecipient, "https://evil.example/acs"},
	}
	for name, swap := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tampered := strings.Replace(document, swap[0], swap[1], 1)
			if tampered == document {
				t.Fatalf("the test did not alter the document")
			}
			if _, err := Verify([]byte(tampered), signer.certificate); !errors.Is(
				err, ErrDigestMismatch) {
				t.Fatalf("Verify() error = %v, want ErrDigestMismatch", err)
			}
		})
	}
}

// TestVerifyRefusesAnotherKeysSignature covers the case where an attacker
// signs a perfectly well-formed assertion with a key the deployment does not
// trust.
func TestVerifyRefusesAnotherKeysSignature(t *testing.T) {
	t.Parallel()
	xmllintPath(t)

	attacker := newTestSigner(t)
	trusted := newTestSigner(t)
	document := attacker.sign(t, unsignedAssertion())

	if _, err := Verify([]byte(document), trusted.certificate); !errors.Is(
		err, ErrSignatureInvalid) {
		t.Fatalf("Verify() error = %v, want ErrSignatureInvalid", err)
	}
}

// TestVerifyRefusesAWrappedSignedAssertion is the wrapping attack driven
// through the real verifier rather than through locate alone: the signature
// and its original assertion are genuine, and a forgery is added alongside.
func TestVerifyRefusesAWrappedSignedAssertion(t *testing.T) {
	t.Parallel()
	xmllintPath(t)

	signer := newTestSigner(t)
	genuine := signer.sign(t, unsignedAssertion())
	forgery := strings.Replace(
		strings.Replace(unsignedAssertion(), `ID="_a1"`, `ID="_a2"`, 1),
		"alice@example.com", "attacker@example.com", 1)

	wrapped := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		genuine + forgery + `</samlp:Response>`
	if _, err := Verify([]byte(wrapped), signer.certificate); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("Verify() error = %v, want ErrAmbiguous", err)
	}
}

// TestVerifyRefusesUnusableKeys covers the branches of key handling that a
// happy-path signature never reaches: a key below the floor, a curve
// mismatch, and a certificate carrying a key type SESAME does not verify.
func TestVerifyRefusesUnusableKeys(t *testing.T) {
	t.Parallel()

	t.Run("RSA below 2048 bits", func(t *testing.T) {
		t.Parallel()

		weak, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("generate weak key: %v", err)
		}
		certificate := &x509.Certificate{PublicKey: &weak.PublicKey}
		err = verifyWithCertificate(certificate, crypto.SHA256, make([]byte, 32), []byte("sig"))
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("error = %v, want ErrSignatureInvalid", err)
		}
		if !strings.Contains(err.Error(), "2048") {
			t.Fatalf("error = %v, want it to name the minimum key size", err)
		}
	})

	t.Run("ECDSA signature of the wrong length", func(t *testing.T) {
		t.Parallel()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		certificate := &x509.Certificate{PublicKey: &key.PublicKey}
		// P-256 expects 64 bytes of r||s; anything else is malformed.
		err = verifyWithCertificate(certificate, crypto.SHA256, make([]byte, 32), make([]byte, 40))
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("error = %v, want ErrSignatureInvalid", err)
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		t.Parallel()

		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		certificate := &x509.Certificate{PublicKey: public}
		if err := verifyWithCertificate(certificate, crypto.SHA256,
			make([]byte, 32), make([]byte, 64)); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("error = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
}
