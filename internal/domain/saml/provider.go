package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	// ProviderIDPrefix distinguishes SAML identity provider identifiers.
	ProviderIDPrefix = "sam_"
	// LoginIDPrefix distinguishes SAML login transactions.
	LoginIDPrefix = "sal_"

	// LoginLifetime bounds how long a SAML login may stay open. It matches
	// the federation slice: generous enough for a person to authenticate
	// including an MFA prompt, short enough that an abandoned transaction is
	// not a standing replay target.
	LoginLifetime = 15 * time.Minute

	// RequestIDBytes is the entropy behind an AuthnRequest identifier. The
	// identifier is what an assertion is bound to through InResponseTo, so it
	// has to be unguessable — a predictable one would let an attacker obtain
	// an assertion that answers a login SESAME is about to start.
	RequestIDBytes = 20

	maxNameLength     = 128
	maxEntityIDLength = 1024
)

// Provider is one external SAML identity provider registered in one tenant.
type Provider struct {
	ID       string `json:"provider_id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	// EntityID is the provider's own identifier and the value every assertion
	// must carry as its Issuer.
	EntityID string `json:"entity_id"`
	// SSOURL is where AuthnRequests are sent.
	SSOURL string `json:"sso_url"`
	// Certificates are the signing certificates SESAME will accept. More than
	// one is normal during a rotation.
	Certificates []string `json:"certificates"`
	// IdentifierNamespace is the SESAME namespace a NameID claims, for the
	// same reason SCIM makes it per-client: SAML does not require a NameID to
	// be an email.
	IdentifierNamespace string `json:"identifier_namespace"`
	Linking             string `json:"linking"`
	Disabled            bool   `json:"disabled,omitempty"`
}

// ProviderRegisteredPayload is the versioned payload of
// EventProviderRegistered. Every field is a scalar or a flat array of
// scalars: FYLO rejects embedded arrays of objects.
type ProviderRegisteredPayload struct {
	ProviderID          string   `json:"provider_id"`
	TenantID            string   `json:"tenant_id"`
	Name                string   `json:"name"`
	EntityID            string   `json:"entity_id"`
	SSOURL              string   `json:"sso_url"`
	Certificates        []string `json:"certificates"`
	IdentifierNamespace string   `json:"identifier_namespace"`
	Linking             string   `json:"linking"`
}

// ProviderDisabledPayload is the versioned payload of EventProviderDisabled.
type ProviderDisabledPayload struct {
	ProviderID string `json:"provider_id"`
	TenantID   string `json:"tenant_id"`
	Reason     string `json:"reason,omitempty"`
}

// LoginStartedPayload is the versioned payload of EventLoginStarted.
type LoginStartedPayload struct {
	LoginID    string `json:"login_id"`
	TenantID   string `json:"tenant_id"`
	ProviderID string `json:"provider_id"`
	// RequestID is not a secret — it travels in the AuthnRequest — so it is
	// stored in the clear. Its unguessability is what matters, not its
	// confidentiality.
	RequestID string `json:"request_id"`
	Recipient string `json:"recipient"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

// LoginCompletedPayload is the versioned payload of EventLoginCompleted.
type LoginCompletedPayload struct {
	LoginID     string `json:"login_id"`
	TenantID    string `json:"tenant_id"`
	ProviderID  string `json:"provider_id"`
	PrincipalID string `json:"principal_id"`
	SubjectHash string `json:"subject_hash"`
	// ReplayKey is the assertion's single-use claim. It is recorded so a
	// restart cannot forget that an assertion was already spent.
	ReplayKey   string `json:"replay_key"`
	Provisioned bool   `json:"provisioned,omitempty"`
	CompletedAt string `json:"completed_at"`
}

// LoginFailedPayload is the versioned payload of EventLoginFailed. The reason
// is a stable code, never the assertion or any part of it.
type LoginFailedPayload struct {
	LoginID    string `json:"login_id"`
	TenantID   string `json:"tenant_id"`
	ProviderID string `json:"provider_id"`
	Reason     string `json:"reason"`
	FailedAt   string `json:"failed_at"`
}

// NewProviderID returns a random provider identifier.
func NewProviderID() (string, error) {
	return randomID(ProviderIDPrefix)
}

// NewLoginID returns a random login identifier.
func NewLoginID() (string, error) {
	return randomID(LoginIDPrefix)
}

func randomID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate identifier: %w", err)
	}
	return prefix + hex.EncodeToString(value), nil
}

// ValidateProviderID rejects values that cannot be provider identifiers.
func ValidateProviderID(id string) error {
	return validateID(id, ProviderIDPrefix, "provider")
}

// ValidateLoginID rejects values that cannot be login identifiers.
func ValidateLoginID(id string) error {
	return validateID(id, LoginIDPrefix, "login")
}

func validateID(id, prefix, what string) error {
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+32 {
		return fmt.Errorf("%s ID must be %s followed by 32 hex characters", what, prefix)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, prefix)); err != nil {
		return fmt.Errorf("%s ID must be %s followed by 32 hex characters", what, prefix)
	}
	return nil
}

// NewRequestID returns an unguessable AuthnRequest identifier.
//
// XML identifiers may not begin with a digit, so it is prefixed. An assertion
// is bound to this value through InResponseTo, and a predictable one would let
// an attacker obtain an assertion answering a login SESAME has not yet made.
func NewRequestID() (string, error) {
	value := make([]byte, RequestIDBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate request identifier: %w", err)
	}
	return "_" + hex.EncodeToString(value), nil
}

// ValidateName enforces a bounded, printable display name.
func ValidateName(name string) error {
	if name == "" || len(name) > maxNameLength {
		return fmt.Errorf("provider name is required and must not exceed %d bytes", maxNameLength)
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return errors.New("provider name must not contain control characters")
		}
	}
	return nil
}

// ValidateEntityID enforces a bounded, printable entity identifier.
//
// A SAML entity ID is a URI but not necessarily a URL, so it is not parsed as
// one. It is compared byte-for-byte against an assertion's Issuer, which is
// why whitespace is refused rather than trimmed: trimming would make SESAME
// accept an Issuer the provider never sends.
func ValidateEntityID(entityID string) error {
	if entityID == "" || len(entityID) > maxEntityIDLength {
		return fmt.Errorf("entity ID is required and must not exceed %d bytes", maxEntityIDLength)
	}
	if strings.TrimSpace(entityID) != entityID {
		return errors.New("entity ID must not have leading or trailing whitespace")
	}
	for _, character := range entityID {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return errors.New("entity ID must not contain whitespace or control characters")
		}
	}
	return nil
}

// ValidateSSOURL enforces an https single sign-on endpoint.
//
// A browser is redirected here carrying an AuthnRequest, and the assertion
// comes back through the browser too. Plaintext would expose the whole flow,
// and there is no loopback exception because the provider is remote.
func ValidateSSOURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("the single sign-on URL is not a valid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return errors.New("the single sign-on URL must use https")
	}
	if parsed.Host == "" {
		return errors.New("the single sign-on URL must include a host")
	}
	if parsed.User != nil {
		return errors.New("the single sign-on URL must not contain userinfo")
	}
	return nil
}

// ParseCertificates decodes the provider's signing certificates.
//
// More than one is normal during a rotation: a provider publishes the new
// certificate before it starts signing with it, and SESAME must accept either
// until the old one is withdrawn.
func ParseCertificates(encoded []string) ([]*x509.Certificate, error) {
	if len(encoded) == 0 {
		return nil, errors.New("a SAML provider requires at least one signing certificate")
	}
	if len(encoded) > 8 {
		return nil, errors.New("a SAML provider must not declare more than 8 certificates")
	}
	certificates := make([]*x509.Certificate, 0, len(encoded))
	for index, value := range encoded {
		certificate, err := parseCertificate(value)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", index, err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

// parseCertificate accepts PEM or bare base64, which is what metadata
// documents and operators respectively tend to supply.
func parseCertificate(value string) (*x509.Certificate, error) {
	trimmed := strings.TrimSpace(value)
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(trimmed), ""))
	if err != nil {
		return nil, fmt.Errorf("the certificate is neither PEM nor base64: %w", err)
	}
	return x509.ParseCertificate(der)
}

// AuthnRequest renders the request that starts a login.
//
// It is deliberately minimal. SESAME does not request a specific
// authentication context, does not force re-authentication, and does not ask
// for a particular NameID format: each of those is a policy an operator may
// want and none can be chosen correctly on their behalf. What it does carry
// is the unguessable ID an assertion must answer.
func AuthnRequest(requestID, issuer, destination, consumerURL string, issued time.Time) string {
	return `<samlp:AuthnRequest ` +
		`xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
		`ID="` + escapeAttribute(requestID) + `" ` +
		`Version="2.0" ` +
		`IssueInstant="` + issued.UTC().Format(time.RFC3339) + `" ` +
		`Destination="` + escapeAttribute(destination) + `" ` +
		`AssertionConsumerServiceURL="` + escapeAttribute(consumerURL) + `" ` +
		`ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">` +
		`<saml:Issuer>` + escapeText(issuer) + `</saml:Issuer>` +
		`</samlp:AuthnRequest>`
}

// RedirectURL builds an HTTP-Redirect binding URL carrying the request.
//
// The engine does this rather than the host. The binding's DEFLATE-then-
// base64 encoding is a protocol decision, and a host that got it subtly wrong
// would produce a login that fails at the provider with nothing in SESAME's
// logs to explain it.
//
// SESAME does not sign the request: a signed AuthnRequest protects the
// provider from forged requests, not SESAME from forged assertions, and every
// assertion is verified on the way back regardless.
func RedirectURL(ssoURL, authnRequest, relayState string) (string, error) {
	parsed, err := url.Parse(ssoURL)
	if err != nil {
		return "", fmt.Errorf("the single sign-on URL is not a valid URL: %w", err)
	}
	encoded, err := deflate(authnRequest)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("SAMLRequest", encoded)
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// deflate applies the redirect binding's raw DEFLATE, which carries no zlib
// or gzip wrapper.
func deflate(request string) (string, error) {
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return "", fmt.Errorf("compress the AuthnRequest: %w", err)
	}
	if _, err := writer.Write([]byte(request)); err != nil {
		return "", fmt.Errorf("compress the AuthnRequest: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("compress the AuthnRequest: %w", err)
	}
	return base64.StdEncoding.EncodeToString(compressed.Bytes()), nil
}

// MaxResponseBytes bounds a decoded SAMLResponse.
//
// An assertion is a small document. Without a bound, a caller could hand the
// engine an arbitrarily large one and make parsing the denial of service.
const MaxResponseBytes = 512 * 1024

// DecodeResponse turns a base64 SAMLResponse form field into the document.
//
// The HTTP-POST binding base64-encodes the response and does not deflate it,
// unlike the redirect binding. Both standard and raw encodings are accepted
// because providers differ on padding; neither changes what the bytes mean.
func DecodeResponse(encoded string) ([]byte, error) {
	trimmed := strings.Join(strings.Fields(encoded), "")
	if trimmed == "" {
		return nil, errors.New("the SAML response is empty")
	}
	// The base64 bound is checked before decoding so an oversized field is
	// refused without allocating it.
	if len(trimmed) > base64.StdEncoding.EncodedLen(MaxResponseBytes) {
		return nil, fmt.Errorf("the SAML response exceeds %d bytes", MaxResponseBytes)
	}
	document, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		document, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil {
		return nil, fmt.Errorf("the SAML response is not base64: %w", err)
	}
	return document, nil
}
