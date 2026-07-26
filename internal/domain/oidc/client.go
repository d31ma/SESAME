// Package oidc defines the relying parties SESAME issues tokens to.
//
// A registered client is the trust anchor of every browser-facing flow: the
// redirect URIs it declares are the only places an authorization response may
// be delivered, and its type decides whether a secret is required. Both are
// validated here rather than at a protocol edge, so a new edge cannot forget
// them.
package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

const (
	// EventClientRegistered records a new relying party.
	EventClientRegistered = "oidc_client.registered"
	// EventClientSecretRotated records a replaced client secret. The old
	// secret stops working at the same moment.
	EventClientSecretRotated = "oidc_client.secret_rotated"
	// EventClientDisabled records a durable, replay-safe client shutdown.
	EventClientDisabled = "oidc_client.disabled"

	// ClientIDPrefix distinguishes public client identifiers.
	ClientIDPrefix = "cli_"

	// TypeConfidential holds a secret it can keep; TypePublic cannot.
	TypeConfidential = "confidential"
	TypePublic       = "public"

	// ScopeOpenID is required of every SESAME client: this is an OpenID
	// Connect surface, not a bare OAuth one.
	ScopeOpenID = "openid"
	// ScopeOfflineAccess is what makes a client eligible for refresh tokens.
	ScopeOfflineAccess = "offline_access"

	maxNameLength         = 128
	maxRedirectURIs       = 16
	maxRedirectURILength  = 512
	maxScopes             = 32
	maxScopeLength        = 64
	clientSecretRandBytes = 32
)

// Client is one registered relying party inside one tenant.
//
// There is no grant-type field on purpose. SESAME issues authorization codes
// and, when offline_access is allowed, refresh tokens; the implicit and
// resource-owner-password grants are not modelled at all, so no configuration
// can turn them on.
type Client struct {
	ID           string   `json:"client_id"`
	TenantID     string   `json:"tenant_id"`
	Name         string   `json:"name"`
	Type         string   `json:"client_type"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	// Audience decides whether the user must be asked. Registering a client
	// declares which scopes it may request — an administrator's decision, not
	// the user's. A third-party client additionally needs recorded consent
	// from the principal whose data is at stake.
	Audience string `json:"audience"`
	// PostLogoutRedirectURIs are the only places a logout may send a browser
	// back to. They are matched exactly, for the same reason redirect URIs
	// are: a loose match here is an open redirect with a friendly name.
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	Disabled               bool     `json:"disabled,omitempty"`
}

// ClientRegisteredPayload is the versioned payload of EventClientRegistered.
// Every field is a scalar or a flat array of scalars: FYLO's document model
// deliberately rejects embedded arrays of objects, and a security event must
// stay one atomic document.
type ClientRegisteredPayload struct {
	ClientID               string   `json:"client_id"`
	TenantID               string   `json:"tenant_id"`
	Name                   string   `json:"name"`
	Type                   string   `json:"client_type"`
	RedirectURIs           []string `json:"redirect_uris"`
	Scopes                 []string `json:"scopes"`
	Audience               string   `json:"audience,omitempty"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	// SecretVerifier is a one-way Argon2id verifier, empty for public
	// clients. The secret itself is returned once at registration and is
	// never recoverable.
	SecretVerifier string `json:"secret_verifier,omitempty"`
}

// ClientSecretRotatedPayload is the versioned payload of
// EventClientSecretRotated.
type ClientSecretRotatedPayload struct {
	ClientID       string `json:"client_id"`
	TenantID       string `json:"tenant_id"`
	SecretVerifier string `json:"secret_verifier"`
}

// ClientDisabledPayload is the versioned payload of EventClientDisabled.
type ClientDisabledPayload struct {
	ClientID string `json:"client_id"`
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason,omitempty"`
}

// NewClientID returns a random public client identifier.
//
// It is an identifier, not a secret: a confidential client also holds a
// separate generated secret, and a public client is authenticated by PKCE and
// its registered redirect URI instead.
func NewClientID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate client identifier: %w", err)
	}
	return ClientIDPrefix + hex.EncodeToString(value), nil
}

// ValidateClientID rejects values that cannot be client identifiers.
func ValidateClientID(id string) error {
	if !strings.HasPrefix(id, ClientIDPrefix) || len(id) != len(ClientIDPrefix)+32 {
		return fmt.Errorf("client ID must be %s followed by 32 hex characters", ClientIDPrefix)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, ClientIDPrefix)); err != nil {
		return fmt.Errorf("client ID must be %s followed by 32 hex characters", ClientIDPrefix)
	}
	return nil
}

// NewClientSecret returns a fresh high-entropy client secret.
func NewClientSecret() (string, error) {
	value := make([]byte, clientSecretRandBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate client secret: %w", err)
	}
	return hex.EncodeToString(value), nil
}

// ValidateType enforces the two modelled client types.
func ValidateType(clientType string) error {
	if clientType != TypeConfidential && clientType != TypePublic {
		return fmt.Errorf("client type must be %q or %q", TypeConfidential, TypePublic)
	}
	return nil
}

// ValidateName enforces a bounded, printable display name.
func ValidateName(name string) error {
	if name == "" || len(name) > maxNameLength {
		return fmt.Errorf("client name is required and must not exceed %d bytes", maxNameLength)
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return errors.New("client name must not contain control characters")
		}
	}
	return nil
}

// NormalizeRedirectURIs validates and canonically orders a redirect set.
//
// Ordering is sorted and deduplicated so one registration always stores
// identically, which keeps the exact-match comparison in MatchRedirectURI a
// simple string equality rather than a normalization decision made at
// request time.
func NormalizeRedirectURIs(uris []string) ([]string, error) {
	if len(uris) == 0 {
		return nil, errors.New("a client requires at least one redirect URI")
	}
	if len(uris) > maxRedirectURIs {
		return nil, fmt.Errorf("a client must not exceed %d redirect URIs", maxRedirectURIs)
	}
	seen := make(map[string]struct{}, len(uris))
	normalized := make([]string, 0, len(uris))
	for _, raw := range uris {
		if err := ValidateRedirectURI(raw); err != nil {
			return nil, err
		}
		if _, duplicate := seen[raw]; duplicate {
			continue
		}
		seen[raw] = struct{}{}
		normalized = append(normalized, raw)
	}
	sort.Strings(normalized)
	return normalized, nil
}

// ValidateRedirectURI enforces the shape an authorization response may be
// delivered to.
//
// The rules are deliberately narrow. Wildcards, path patterns, and prefix
// matching are the classic route to an open redirect and to authorization
// codes delivered to an attacker, so a redirect URI must be a complete,
// absolute, fragment-free https URI — or a loopback http URI, which never
// leaves the user's machine (RFC 8252 section 7.3).
func ValidateRedirectURI(raw string) error {
	if raw == "" || len(raw) > maxRedirectURILength {
		return fmt.Errorf("redirect URI is required and must not exceed %d bytes", maxRedirectURILength)
	}
	if strings.ContainsAny(raw, "*") {
		return fmt.Errorf("redirect URI %q must not contain a wildcard", raw)
	}
	// url.Parse is lenient about whitespace and control characters. They have
	// no place in a registered URI and are how request smuggling gets in.
	for _, character := range raw {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return fmt.Errorf("redirect URI %q must not contain whitespace or control characters", raw)
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect URI %q is not a valid URI", raw)
	}
	if parsed.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("redirect URI %q must not contain a fragment", raw)
	}
	if parsed.Host == "" {
		return fmt.Errorf("redirect URI %q must be absolute", raw)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("redirect URI %q may only use http on a loopback address", raw)
	default:
		// ponytail: private-use schemes for native apps (RFC 8252 section
		// 7.1) are not accepted yet; add them with their own reverse-DNS
		// validation when a native client needs one.
		return fmt.Errorf("redirect URI %q must use https, or http on a loopback address", raw)
	}
}

func isLoopback(host string) bool {
	// "localhost" is accepted alongside the literal addresses because it is
	// what developer tooling emits; it resolves to a loopback address on
	// every platform SESAME supports.
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// MatchRedirectURI reports whether a requested redirect URI is registered.
// The comparison is exact string equality, by design.
func MatchRedirectURI(registered []string, requested string) bool {
	for _, candidate := range registered {
		if candidate == requested {
			return true
		}
	}
	return false
}

// NormalizePostLogoutRedirectURIs validates and canonically orders the URIs a
// logout may return a browser to. An empty set is allowed: a client that never
// redirects after logout needs none.
func NormalizePostLogoutRedirectURIs(uris []string) ([]string, error) {
	if len(uris) == 0 {
		return nil, nil
	}
	if len(uris) > maxRedirectURIs {
		return nil, fmt.Errorf("a client must not exceed %d post-logout redirect URIs", maxRedirectURIs)
	}
	seen := make(map[string]struct{}, len(uris))
	normalized := make([]string, 0, len(uris))
	for _, raw := range uris {
		if err := ValidateRedirectURI(raw); err != nil {
			return nil, err
		}
		if _, duplicate := seen[raw]; duplicate {
			continue
		}
		seen[raw] = struct{}{}
		normalized = append(normalized, raw)
	}
	sort.Strings(normalized)
	return normalized, nil
}

// NormalizeScopes validates and canonically orders a scope set, requiring
// "openid".
func NormalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) > maxScopes {
		return nil, fmt.Errorf("a client must not exceed %d scopes", maxScopes)
	}
	seen := make(map[string]struct{}, len(scopes)+1)
	normalized := make([]string, 0, len(scopes)+1)
	for _, scope := range scopes {
		if err := ValidateScope(scope); err != nil {
			return nil, err
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	if _, present := seen[ScopeOpenID]; !present {
		normalized = append(normalized, ScopeOpenID)
	}
	sort.Strings(normalized)
	return normalized, nil
}

// ValidateScope enforces the bounded scope-token shape from RFC 6749.
func ValidateScope(scope string) error {
	if scope == "" || len(scope) > maxScopeLength {
		return fmt.Errorf("scope is required and must not exceed %d bytes", maxScopeLength)
	}
	for _, character := range scope {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '_' || character == '-' || character == '.' || character == ':':
		default:
			return fmt.Errorf("scope %q contains unsupported character %q", scope, character)
		}
	}
	return nil
}

// AllowsScopes reports whether every requested scope is registered, naming
// the first that is not.
func (c Client) AllowsScopes(requested []string) (bool, string) {
	allowed := make(map[string]struct{}, len(c.Scopes))
	for _, scope := range c.Scopes {
		allowed[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowed[scope]; !ok {
			return false, scope
		}
	}
	return true, ""
}
