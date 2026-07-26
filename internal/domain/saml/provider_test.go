package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestValidateEntityIDRefusesWhatCannotBeComparedExactly(t *testing.T) {
	t.Parallel()

	// An entity ID is compared byte-for-byte against an assertion's Issuer,
	// so whitespace is refused rather than trimmed: trimming would make
	// SESAME accept an Issuer the provider never sends.
	refused := map[string]string{
		"empty":             "",
		"leading space":     " https://idp.example/metadata",
		"trailing space":    "https://idp.example/metadata ",
		"embedded space":    "https://idp.example/meta data",
		"embedded tab":      "https://idp.example/meta\tdata",
		"embedded newline":  "https://idp.example/meta\ndata",
		"control character": "https://idp.example/meta\x00data",
		"too long":          strings.Repeat("a", maxEntityIDLength+1),
	}
	for name, value := range refused {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateEntityID(value); err == nil {
				t.Fatalf("ValidateEntityID(%q) accepted it", value)
			}
		})
	}
	// A SAML entity ID is a URI but not necessarily a URL, so a plain URN
	// must be accepted.
	for _, value := range []string{
		"https://idp.example/metadata",
		"urn:example:idp",
		"http://idp.example/metadata",
	} {
		if err := ValidateEntityID(value); err != nil {
			t.Fatalf("ValidateEntityID(%q) error = %v", value, err)
		}
	}
}

func TestValidateSSOURLRequiresHTTPS(t *testing.T) {
	t.Parallel()

	// A browser carries the AuthnRequest here and the assertion comes back
	// through the browser too, so plaintext would expose the whole flow.
	// There is no loopback exception: the provider is remote.
	refused := map[string]string{
		"plaintext":          "http://idp.example/sso",
		"plaintext loopback": "http://127.0.0.1:8443/sso",
		"no scheme":          "idp.example/sso",
		"no host":            "https:///sso",
		"userinfo":           "https://user:pass@idp.example/sso",
		"not a URL":          "https://idp.example/%zz",
		"empty":              "",
	}
	for name, value := range refused {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateSSOURL(value); err == nil {
				t.Fatalf("ValidateSSOURL(%q) accepted it", value)
			}
		})
	}
	if err := ValidateSSOURL("https://idp.example/sso?idp=1"); err != nil {
		t.Fatalf("ValidateSSOURL() error = %v", err)
	}
}

func TestValidateNameBoundsAndPrintability(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"empty":             "",
		"too long":          strings.Repeat("a", maxNameLength+1),
		"control character": "Corp\x07SSO",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateName(value); err == nil {
				t.Fatalf("ValidateName(%q) accepted it", value)
			}
		})
	}
	if err := ValidateName("Corp SSO — Europe"); err != nil {
		t.Fatalf("ValidateName() error = %v", err)
	}
}

func TestParseCertificatesAcceptsPEMAndBareBase64(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	der := signer.certificate.Raw
	bare := base64.StdEncoding.EncodeToString(der)
	pemForm := "-----BEGIN CERTIFICATE-----\n" +
		wrapBase64(bare) + "-----END CERTIFICATE-----\n"
	// Metadata documents wrap the base64 across lines without PEM armour,
	// which is what an operator copies out of one.
	wrapped := wrapBase64(bare)

	for name, encoded := range map[string]string{
		"PEM":            pemForm,
		"bare base64":    bare,
		"wrapped base64": wrapped,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsed, err := ParseCertificates([]string{encoded})
			if err != nil {
				t.Fatalf("ParseCertificates() error = %v", err)
			}
			if !bytes.Equal(parsed[0].Raw, der) {
				t.Fatal("the parsed certificate is not the one supplied")
			}
		})
	}
}

func TestParseCertificatesRefusesUnusableInput(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	valid := base64.StdEncoding.EncodeToString(signer.certificate.Raw)
	many := make([]string, 9)
	for index := range many {
		many[index] = valid
	}

	for name, encoded := range map[string][]string{
		// A provider with no certificate cannot be verified at all, so
		// registering one would create a provider nobody could log in through.
		"none":               nil,
		"empty string":       {""},
		"not base64":         {"!!! not base64 !!!"},
		"base64 but not DER": {base64.StdEncoding.EncodeToString([]byte("hello"))},
		// A bound, so a registration cannot make every login walk a long list.
		"more than eight": many,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseCertificates(encoded); err == nil {
				t.Fatalf("ParseCertificates(%d values) accepted it", len(encoded))
			}
		})
	}

	// A rotation is the normal case for two, and the error must name which
	// one is broken.
	_, err := ParseCertificates([]string{valid, "broken"})
	if err == nil || !strings.Contains(err.Error(), "certificate 1") {
		t.Fatalf("error = %v, want it to name the offending certificate", err)
	}
}

func TestIdentifiersAreUnguessableAndValidated(t *testing.T) {
	t.Parallel()

	providerID, err := NewProviderID()
	if err != nil {
		t.Fatalf("NewProviderID() error = %v", err)
	}
	if err := ValidateProviderID(providerID); err != nil {
		t.Fatalf("ValidateProviderID(%q) error = %v", providerID, err)
	}
	loginID, err := NewLoginID()
	if err != nil {
		t.Fatalf("NewLoginID() error = %v", err)
	}
	if err := ValidateLoginID(loginID); err != nil {
		t.Fatalf("ValidateLoginID(%q) error = %v", loginID, err)
	}
	// A login ID is not a provider ID, and neither validator may accept the
	// other's prefix.
	if ValidateProviderID(loginID) == nil || ValidateLoginID(providerID) == nil {
		t.Fatal("the identifier validators accept each other's values")
	}
	for name, value := range map[string]string{
		"no prefix":     strings.TrimPrefix(providerID, ProviderIDPrefix),
		"short":         ProviderIDPrefix + "abcd",
		"not hex":       ProviderIDPrefix + strings.Repeat("z", 32),
		"empty":         "",
		"prefix only":   ProviderIDPrefix,
		"wrong padding": ProviderIDPrefix + strings.Repeat("a", 33),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := ValidateProviderID(value); err == nil {
				t.Fatalf("ValidateProviderID(%q) accepted it", value)
			}
		})
	}
}

// TestNewRequestIDIsUnguessableAndAnXMLName: an assertion is bound to this
// value through InResponseTo, so a predictable one would let an attacker
// obtain an assertion answering a login SESAME has not yet started. XML also
// forbids an identifier beginning with a digit.
func TestNewRequestIDIsUnguessableAndAnXMLName(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for range 128 {
		requestID, err := NewRequestID()
		if err != nil {
			t.Fatalf("NewRequestID() error = %v", err)
		}
		if !strings.HasPrefix(requestID, "_") {
			t.Fatalf("request ID %q does not begin with an XML name start character", requestID)
		}
		if len(requestID) != 1+2*RequestIDBytes {
			t.Fatalf("request ID %q is %d characters", requestID, len(requestID))
		}
		if seen[requestID] {
			t.Fatalf("NewRequestID repeated %q", requestID)
		}
		seen[requestID] = true
	}
}

// TestAuthnRequestCarriesWhatAnAssertionMustAnswer.
func TestAuthnRequestCarriesWhatAnAssertionMustAnswer(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	request := AuthnRequest("_req1", "https://sesame.example",
		"https://idp.example/sso", "https://app.example/acs", issued)

	for _, wanted := range []string{
		`ID="_req1"`,
		`Version="2.0"`,
		`IssueInstant="2026-01-01T12:00:00Z"`,
		`Destination="https://idp.example/sso"`,
		`AssertionConsumerServiceURL="https://app.example/acs"`,
		`<saml:Issuer>https://sesame.example</saml:Issuer>`,
	} {
		if !strings.Contains(request, wanted) {
			t.Fatalf("the AuthnRequest is missing %s:\n%s", wanted, request)
		}
	}
	// A consumer URL carrying XML metacharacters must be escaped, not
	// injected: the host chooses it, and a host is not a trusted author of
	// SESAME's XML.
	hostile := AuthnRequest("_req1", `a"><evil/><x y="`, "https://idp.example/sso",
		"https://app.example/acs", issued)
	if strings.Contains(hostile, "<evil/>") {
		t.Fatalf("an issuer injected an element into the AuthnRequest:\n%s", hostile)
	}
}

// TestRedirectURLEncodesTheBinding proves the engine produces a URL a
// provider can actually decode, by decoding it the way one would.
func TestRedirectURLEncodesTheBinding(t *testing.T) {
	t.Parallel()

	request := AuthnRequest("_req1", "https://sesame.example",
		"https://idp.example/sso", "https://app.example/acs", time.Now())
	redirect, err := RedirectURL("https://idp.example/sso?tenant=acme", request, "sal_state")
	if err != nil {
		t.Fatalf("RedirectURL() error = %v", err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// A query the provider already required must survive.
	if parsed.Query().Get("tenant") != "acme" {
		t.Fatalf("the provider's own query parameter was dropped: %s", redirect)
	}
	if parsed.Query().Get("RelayState") != "sal_state" {
		t.Fatalf("RelayState = %q", parsed.Query().Get("RelayState"))
	}

	compressed, err := base64.StdEncoding.DecodeString(parsed.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("SAMLRequest is not base64: %v", err)
	}
	// The binding uses raw DEFLATE with no zlib or gzip wrapper.
	decoded, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	if err != nil {
		t.Fatalf("SAMLRequest is not raw DEFLATE: %v", err)
	}
	if string(decoded) != request {
		t.Fatalf("the decoded request differs from the one sent:\n%s", decoded)
	}

	// No RelayState means no parameter, rather than an empty one.
	plain, err := RedirectURL("https://idp.example/sso", request, "")
	if err != nil {
		t.Fatalf("RedirectURL() error = %v", err)
	}
	if strings.Contains(plain, "RelayState") {
		t.Fatalf("an empty RelayState was still sent: %s", plain)
	}
	if _, err := RedirectURL("https://idp.example/%zz", request, ""); err == nil {
		t.Fatal("RedirectURL accepted an unparseable single sign-on URL")
	}
}

// TestDecodeResponseBoundsAndFormats.
func TestDecodeResponseBoundsAndFormats(t *testing.T) {
	t.Parallel()

	document := "<saml:Assertion/>"
	standard := base64.StdEncoding.EncodeToString([]byte(document))
	raw := base64.RawStdEncoding.EncodeToString([]byte(document))

	for name, encoded := range map[string]string{
		// Providers differ on padding; neither changes what the bytes mean.
		"padded":               standard,
		"unpadded":             raw,
		"wrapped across lines": standard[:4] + "\n" + standard[4:],
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			decoded, err := DecodeResponse(encoded)
			if err != nil {
				t.Fatalf("DecodeResponse() error = %v", err)
			}
			if string(decoded) != document {
				t.Fatalf("decoded %q", decoded)
			}
		})
	}

	for name, encoded := range map[string]string{
		"empty":      "",
		"whitespace": "   \n\t ",
		"not base64": "!!! not base64 !!!",
		// The bound is checked before decoding, so an oversized field is
		// refused without allocating it.
		"oversized": strings.Repeat("A", base64.StdEncoding.EncodedLen(MaxResponseBytes)+4),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := DecodeResponse(encoded); err == nil {
				t.Fatalf("DecodeResponse accepted %d characters of %s", len(encoded), name)
			}
		})
	}
}

// wrapBase64 breaks a base64 string into 64-character lines, as certificate
// files and metadata documents do.
func wrapBase64(value string) string {
	var wrapped strings.Builder
	for len(value) > 64 {
		wrapped.WriteString(value[:64])
		wrapped.WriteString("\n")
		value = value[64:]
	}
	wrapped.WriteString(value)
	wrapped.WriteString("\n")
	return wrapped.String()
}
