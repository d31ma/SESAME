package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

const (
	namespaceSignature = "http://www.w3.org/2000/09/xmldsig#"
	namespaceAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	namespaceProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"

	algorithmExclusiveC14N             = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algorithmExclusiveC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	transformEnvelopedSignature        = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

var (
	// ErrNoSignature reports a document with nothing to verify. It is not a
	// tolerable state: an unsigned assertion is an assertion anyone can write.
	ErrNoSignature = errors.New("the SAML document carries no signature")
	// ErrUnsupportedAlgorithm reports an algorithm outside the allowlist.
	ErrUnsupportedAlgorithm = errors.New("unsupported SAML signature algorithm")
	// ErrSignatureInvalid reports a signature that does not verify.
	ErrSignatureInvalid = errors.New("the SAML signature is invalid")
	// ErrDigestMismatch reports a reference whose digest does not match the
	// canonical form of the element it names — the document was altered after
	// signing.
	ErrDigestMismatch = errors.New("the signed element does not match its digest")
)

// signatureAlgorithms is the closed allowlist.
//
// SHA-1 is absent: collisions are practical and a SHA-1 signature is not
// evidence. HMAC methods are absent because an identity provider's
// certificate is public, and accepting one would let anyone holding it mint
// assertions.
var signatureAlgorithms = map[string]struct {
	hash    crypto.Hash
	newHash func() hash.Hash
}{
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   {crypto.SHA256, sha256.New},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   {crypto.SHA384, sha512.New384},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   {crypto.SHA512, sha512.New},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": {crypto.SHA256, sha256.New},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": {crypto.SHA384, sha512.New384},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": {crypto.SHA512, sha512.New},
}

var digestAlgorithms = map[string]func() hash.Hash{
	"http://www.w3.org/2001/04/xmlenc#sha256":       sha256.New,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": sha512.New384,
	"http://www.w3.org/2001/04/xmlenc#sha512":       sha512.New,
}

// SupportedSignatureAlgorithms lists what SESAME will verify.
func SupportedSignatureAlgorithms() []string {
	return []string{
		"rsa-sha256", "rsa-sha384", "rsa-sha512",
		"ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512",
	}
}

// Signed is the result of verification: the byte range that was signed.
//
// It carries bytes rather than a parsed document on purpose. The caller reads
// its subject and conditions from `Element` alone and never re-queries the
// original, which is what makes XML Signature Wrapping structurally
// impossible here — there is no second place to read from.
type Signed struct {
	// Element is the canonical-source byte range of the signed element,
	// extracted from the original document.
	Element []byte
	// Name identifies what was signed, so a caller can refuse a signature
	// over the wrong kind of element.
	Name xml.Name
	// ID is the element's identifier, which the reference named.
	ID string
	// Inherited are the namespace bindings in scope at the signed element but
	// declared on its ancestors, and therefore outside Element.
	//
	// Without them the extracted bytes are not a parseable document. A real
	// provider writes `<saml:Assertion>` and binds `saml:` once, up on the
	// enclosing Response — so the subtree on its own refers to a prefix
	// nothing declares. Canonicalization already needed these; parsing needs
	// them for the same reason, and not carrying them here is what made
	// SESAME's verifier work on its own fixtures and fail on Keycloak's.
	Inherited map[string]string
}

// Verify checks a SAML document's signature and returns what it covers.
//
// The order is deliberate: locate exactly one signature, resolve its
// reference to exactly one element, verify that element's digest, then verify
// the signature over SignedInfo. Nothing in the document is trusted before
// all four succeed.
func Verify(document []byte, certificate *x509.Certificate) (Signed, error) {
	if len(document) == 0 {
		return Signed{}, errors.New("the SAML document is empty")
	}
	if len(document) > MaxDocumentBytes {
		return Signed{}, ErrDocumentTooLarge
	}
	located, err := locate(document)
	if err != nil {
		return Signed{}, err
	}
	if err := verifyReference(document, located); err != nil {
		return Signed{}, err
	}
	if err := verifySignatureValue(document, located, certificate); err != nil {
		return Signed{}, err
	}
	return Signed{
		Element:   document[located.Signed.Start:located.Signed.End],
		Name:      located.Signed.Name,
		ID:        located.Signed.ID,
		Inherited: located.Inherited,
	}, nil
}

// verifyReference recomputes the signed element's digest.
func verifyReference(document []byte, located located) error {
	newDigest, supported := digestAlgorithms[located.DigestMethod]
	if !supported {
		return fmt.Errorf("%w: digest %q", ErrUnsupportedAlgorithm, located.DigestMethod)
	}
	// The enveloped-signature transform removes the Signature element from
	// the subtree before digesting. Without excising it the digest could
	// never match, because the signature cannot cover itself.
	subtree, err := canonicalizeExcluding(document, located.Signed, located.Signature,
		located.C14NWithComments, located.Inherited)
	if err != nil {
		return err
	}
	digest := newDigest()
	digest.Write(subtree)
	expected, err := base64.StdEncoding.DecodeString(strings.TrimSpace(located.DigestValue))
	if err != nil {
		return fmt.Errorf("%w: the digest value is not base64", ErrDigestMismatch)
	}
	if !equalBytes(digest.Sum(nil), expected) {
		return ErrDigestMismatch
	}
	return nil
}

// verifySignatureValue checks the signature over the canonical SignedInfo.
func verifySignatureValue(
	document []byte,
	located located,
	certificate *x509.Certificate,
) error {
	spec, supported := signatureAlgorithms[located.SignatureMethod]
	if !supported {
		return fmt.Errorf("%w: %q (SESAME accepts %s)", ErrUnsupportedAlgorithm,
			located.SignatureMethod, strings.Join(SupportedSignatureAlgorithms(), ", "))
	}
	signedInfo, err := canonicalize(document, located.SignedInfo, located.C14NWithComments,
		located.SignedInfoInherited)
	if err != nil {
		return err
	}
	digest := spec.newHash()
	digest.Write(signedInfo)
	sum := digest.Sum(nil)

	signature, err := base64.StdEncoding.DecodeString(
		strings.Join(strings.Fields(located.SignatureValue), ""))
	if err != nil {
		return fmt.Errorf("%w: the signature value is not base64", ErrSignatureInvalid)
	}
	return verifyWithCertificate(certificate, spec.hash, sum, signature)
}

func verifyWithCertificate(
	certificate *x509.Certificate,
	hashed crypto.Hash,
	sum, signature []byte,
) error {
	switch public := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		// 2048 bits is the floor every current guideline agrees on.
		if public.N.BitLen() < 2048 {
			return fmt.Errorf("%w: the provider's RSA key is %d bits, below 2048",
				ErrSignatureInvalid, public.N.BitLen())
		}
		if err := rsa.VerifyPKCS1v15(public, hashed, sum, signature); err != nil {
			return ErrSignatureInvalid
		}
		return nil
	case *ecdsa.PublicKey:
		// XML DSig uses the fixed-width r||s form, as JOSE does.
		size := (public.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return fmt.Errorf("%w: the signature has the wrong length for its curve",
				ErrSignatureInvalid)
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(public, sum, r, s) {
			return ErrSignatureInvalid
		}
		return nil
	default:
		return fmt.Errorf("%w: the certificate carries an unsupported key type",
			ErrUnsupportedAlgorithm)
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
