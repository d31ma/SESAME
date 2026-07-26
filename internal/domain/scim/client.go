// Package scim models SESAME as a SCIM 2.0 service provider: an external
// identity provider pushes users and groups here, over RFC 7644's protocol
// and RFC 7643's schema.
//
// SESAME opens no port, so the host exposes the `/scim/v2` routes and carries
// each request to the engine over the machine protocol. The HTTP shape —
// methods, status codes, `Location` headers — belongs to the host adapter;
// every decision about what a request means and whether it is allowed belongs
// here. That split is ADR 0003's standards-dispatch boundary.
//
// Provisioning is the most privileged non-administrative surface SESAME has.
// A provisioning client can create principals, change their identifiers, and
// move them in and out of groups — and groups drive authorization decisions,
// so group membership is a privilege-granting operation wearing a
// directory-sync costume. Everything here is written with that in mind.
package scim

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	// EventClientRegistered records a new provisioning client.
	EventClientRegistered = "scim_client.registered"
	// EventClientTokenRotated records a replaced bearer token. The old token
	// stops working at the same moment.
	EventClientTokenRotated = "scim_client.token_rotated"
	// EventClientDisabled records a durable, replay-safe shutdown.
	EventClientDisabled = "scim_client.disabled"

	// ClientIDPrefix distinguishes provisioning client identifiers.
	ClientIDPrefix = "scm_"

	// tokenBytes is the entropy behind a provisioning token. It is
	// bearer-equivalent: whoever holds it can provision.
	tokenBytes = 32

	maxNameLength = 128
)

// Client is one external system permitted to provision into one tenant.
//
// There is no per-resource permission model. A provisioning client either may
// provision this tenant or it may not, which is what SCIM deployments
// actually configure. Narrowing it further would invent a model no identity
// provider knows how to drive.
type Client struct {
	ID       string `json:"scim_client_id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	// CanManageGroups gates the one operation that grants privilege. A
	// provisioning client that only needs to create and deactivate people
	// should not also be able to add them to a group that carries a role.
	CanManageGroups bool `json:"can_manage_groups"`
	// IdentifierNamespace is the SESAME identifier namespace a SCIM
	// `userName` claims. It is per-client rather than fixed because SCIM
	// does not require userName to be an email, and choosing one globally
	// would either break directories that use a login name or split a person
	// into two principals when they later sign in through federation.
	IdentifierNamespace string `json:"identifier_namespace"`
	Disabled            bool   `json:"disabled,omitempty"`
}

// DefaultIdentifierNamespace is what a provisioning client claims when it
// names none. Most directories send an email address as userName, and
// matching federation's namespace means a provisioned user and a federated
// one converge on the same principal instead of becoming two.
const DefaultIdentifierNamespace = "email"

// NormalizeIdentifierNamespace applies the default and bounds the value.
func NormalizeIdentifierNamespace(namespace string) (string, error) {
	if namespace == "" {
		return DefaultIdentifierNamespace, nil
	}
	if len(namespace) > 64 {
		return "", errors.New("identifier namespace must not exceed 64 bytes")
	}
	for _, character := range namespace {
		if !unicode.IsLower(character) && !unicode.IsDigit(character) && character != '_' {
			return "", errors.New(
				"identifier namespace must be lowercase letters, digits, or underscores")
		}
	}
	return namespace, nil
}

// ClientRegisteredPayload is the versioned payload of EventClientRegistered.
type ClientRegisteredPayload struct {
	ClientID            string `json:"scim_client_id"`
	TenantID            string `json:"tenant_id"`
	Name                string `json:"name"`
	CanManageGroups     bool   `json:"can_manage_groups"`
	IdentifierNamespace string `json:"identifier_namespace"`
	// TokenDigest is a one-way SHA-256 digest. The token is returned once at
	// registration and is never recoverable.
	TokenDigest string `json:"token_digest"`
}

// ClientTokenRotatedPayload is the versioned payload of
// EventClientTokenRotated.
type ClientTokenRotatedPayload struct {
	ClientID    string `json:"scim_client_id"`
	TenantID    string `json:"tenant_id"`
	TokenDigest string `json:"token_digest"`
}

// ClientDisabledPayload is the versioned payload of EventClientDisabled.
type ClientDisabledPayload struct {
	ClientID string `json:"scim_client_id"`
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason,omitempty"`
}

// NewClientID returns a random provisioning client identifier.
func NewClientID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate provisioning client identifier: %w", err)
	}
	return ClientIDPrefix + hex.EncodeToString(value), nil
}

// ValidateClientID rejects values that cannot be client identifiers.
func ValidateClientID(id string) error {
	if !strings.HasPrefix(id, ClientIDPrefix) || len(id) != len(ClientIDPrefix)+32 {
		return fmt.Errorf("provisioning client ID must be %s followed by 32 hex characters",
			ClientIDPrefix)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, ClientIDPrefix)); err != nil {
		return fmt.Errorf("provisioning client ID must be %s followed by 32 hex characters",
			ClientIDPrefix)
	}
	return nil
}

// NewToken returns a fresh bearer token and the digest to store.
func NewToken() (token string, digest string, err error) {
	value := make([]byte, tokenBytes)
	if _, err := rand.Read(value); err != nil {
		return "", "", fmt.Errorf("generate provisioning token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(value)
	return token, Digest(token), nil
}

// Digest hashes a provisioning token for storage and comparison.
//
// SHA-256 without a password-hashing construction, for the same reason a
// session secret uses one: the token is 256 bits of uniform randomness, so
// there is no guessable input space for an attacker to work through, and
// every provisioning request pays this cost.
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// VerifyToken compares a presented token against a stored digest in constant
// time.
func VerifyToken(presented, storedDigest string) bool {
	if presented == "" || storedDigest == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(Digest(presented)), []byte(storedDigest)) == 1
}

// ValidateName enforces a bounded, printable display name.
func ValidateName(name string) error {
	if name == "" || len(name) > maxNameLength {
		return fmt.Errorf(
			"provisioning client name is required and must not exceed %d bytes", maxNameLength)
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return errors.New(
				"provisioning client name must not contain control characters")
		}
	}
	return nil
}

// ParseBearer extracts a token from an Authorization header value.
//
// The scheme is compared case-insensitively because RFC 7235 says it is, and
// a provider that sends "bearer" would otherwise fail in a way nobody can
// diagnose from the outside.
func ParseBearer(header string) (string, error) {
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", errors.New("Authorization must be a Bearer credential")
	}
	token := strings.TrimSpace(header[len(scheme):])
	if token == "" {
		return "", errors.New("Authorization carries no credential")
	}
	return token, nil
}
