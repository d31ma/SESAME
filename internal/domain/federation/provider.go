// Package federation models inbound OpenID Connect federation: SESAME acting
// as a relying party to an external OpenID Provider.
//
// The engine performs no network I/O. It names the exact URL to fetch, the
// host fetches it, and everything that comes back is parsed and validated
// here as untrusted input. See docs/adr/0004-federation-egress-boundary.md
// for why that boundary is where it is.
//
// The registered issuer is the trust anchor for the whole flow. A discovery
// document may describe a provider's endpoints, but it may not move them to
// another origin, downgrade their scheme, or introduce an algorithm outside
// the allowlist. Everything a remote server says is checked against what an
// administrator registered.
package federation

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
	// EventProviderRegistered records a new external identity provider.
	EventProviderRegistered = "federation.provider_registered"
	// EventProviderUpdated records changed provider configuration.
	EventProviderUpdated = "federation.provider_updated"
	// EventProviderDisabled records a durable provider shutdown. Existing
	// links survive; new federated logins stop immediately.
	EventProviderDisabled = "federation.provider_disabled"

	// ProviderIDPrefix distinguishes external provider identifiers.
	ProviderIDPrefix = "idp_"

	// ScopeOpenID is required of every federated request: SESAME needs an ID
	// token, and without this scope it will not get one.
	ScopeOpenID = "openid"

	// LinkingStrict requires an administrator to link the external subject to
	// a principal before any federated login succeeds.
	LinkingStrict = "strict"
	// LinkingVerifiedEmail links on a verified email claim matching an
	// existing identifier, and provisions a new principal when none matches.
	LinkingVerifiedEmail = "verified_email"

	maxNameLength     = 128
	maxIssuerLength   = 512
	maxScopes         = 32
	maxScopeLength    = 64
	maxClaimKeyLength = 128
)

// Provider is one external OpenID Provider registered inside one tenant.
//
// There is no field for a token endpoint, JWKS URI, or authorization
// endpoint. Those come from the provider's discovery document and are
// re-derived against Issuer every time, so a compromised provider cannot
// persist a redirected endpoint into SESAME's own state.
type Provider struct {
	ID       string `json:"provider_id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	// Issuer is the trust anchor: the exact `iss` every ID token must carry
	// and the origin every endpoint must belong to.
	Issuer string `json:"issuer"`
	// ClientID is what the external provider knows SESAME as.
	ClientID string `json:"client_id"`
	// Scopes are requested at the provider. openid is always included.
	Scopes []string `json:"scopes"`
	// SubjectClaim names the claim carrying the provider's stable user
	// identifier. Defaults to sub, which is the only claim OpenID Connect
	// guarantees is stable and unique for a provider.
	SubjectClaim string `json:"subject_claim"`
	// EmailClaim names the claim carrying an email address, used by
	// verified-email linking.
	EmailClaim string `json:"email_claim,omitempty"`
	// Linking decides what a successful assertion is allowed to do: match an
	// existing principal, or create one.
	Linking  string `json:"linking"`
	Disabled bool   `json:"disabled,omitempty"`
}

// ProviderRegisteredPayload is the versioned payload of
// EventProviderRegistered. Every field is a scalar or a flat array of
// scalars: FYLO rejects embedded arrays of objects, and a security event must
// stay one atomic document.
type ProviderRegisteredPayload struct {
	ProviderID   string   `json:"provider_id"`
	TenantID     string   `json:"tenant_id"`
	Name         string   `json:"name"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	Scopes       []string `json:"scopes"`
	SubjectClaim string   `json:"subject_claim"`
	EmailClaim   string   `json:"email_claim,omitempty"`
	Linking      string   `json:"linking"`
	// SecretSealed is the provider's client secret under AES-256-GCM. Unlike
	// a SESAME client secret, this one must be replayed to the provider's
	// token endpoint on every exchange, so it is encrypted rather than
	// hashed.
	SecretSealed string `json:"secret_sealed,omitempty"`
}

// ProviderUpdatedPayload is the versioned payload of EventProviderUpdated.
type ProviderUpdatedPayload struct {
	ProviderID   string   `json:"provider_id"`
	TenantID     string   `json:"tenant_id"`
	Name         string   `json:"name"`
	Scopes       []string `json:"scopes"`
	SubjectClaim string   `json:"subject_claim"`
	EmailClaim   string   `json:"email_claim,omitempty"`
	Linking      string   `json:"linking"`
	SecretSealed string   `json:"secret_sealed,omitempty"`
}

// ProviderDisabledPayload is the versioned payload of EventProviderDisabled.
type ProviderDisabledPayload struct {
	ProviderID string `json:"provider_id"`
	TenantID   string `json:"tenant_id"`
	Reason     string `json:"reason,omitempty"`
}

// NewProviderID returns a random public provider identifier.
func NewProviderID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate provider identifier: %w", err)
	}
	return ProviderIDPrefix + hex.EncodeToString(value), nil
}

// ValidateProviderID rejects values that cannot be provider identifiers.
func ValidateProviderID(id string) error {
	if !strings.HasPrefix(id, ProviderIDPrefix) || len(id) != len(ProviderIDPrefix)+32 {
		return fmt.Errorf("provider ID must be %s followed by 32 hex characters", ProviderIDPrefix)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, ProviderIDPrefix)); err != nil {
		return fmt.Errorf("provider ID must be %s followed by 32 hex characters", ProviderIDPrefix)
	}
	return nil
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

// NormalizeIssuer validates an issuer and returns its canonical form.
//
// OpenID Connect compares `iss` by exact string equality, so the stored form
// has to be the form that will arrive in a token. Normalization is therefore
// deliberately minimal — a trailing slash is refused rather than trimmed,
// because trimming would make SESAME accept an issuer the provider never
// sends.
func NormalizeIssuer(issuer string) (string, error) {
	if issuer == "" || len(issuer) > maxIssuerLength {
		return "", fmt.Errorf("issuer is required and must not exceed %d bytes", maxIssuerLength)
	}
	if strings.TrimSpace(issuer) != issuer {
		return "", errors.New("issuer must not have leading or trailing whitespace")
	}
	for _, character := range issuer {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return "", errors.New("issuer must not contain whitespace or control characters")
		}
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("issuer is not a valid URL: %w", err)
	}
	// https only. A federated login carries an authorization code and an ID
	// token; plaintext would expose both, and there is no loopback exception
	// because the provider is by definition remote.
	if parsed.Scheme != "https" {
		return "", errors.New("issuer must use https")
	}
	if parsed.Host == "" {
		return "", errors.New("issuer must include a host")
	}
	if parsed.User != nil {
		return "", errors.New("issuer must not contain userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("issuer must not contain a query or fragment")
	}
	if strings.HasSuffix(parsed.Path, "/") {
		return "", errors.New("issuer must not end in a trailing slash")
	}
	return parsed.String(), nil
}

// NormalizeScopes validates and canonically orders a scope set, ensuring
// openid is present.
func NormalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) > maxScopes {
		return nil, fmt.Errorf("a provider must not exceed %d scopes", maxScopes)
	}
	seen := map[string]struct{}{ScopeOpenID: {}}
	normalized := []string{ScopeOpenID}
	for _, scope := range scopes {
		if scope == "" || len(scope) > maxScopeLength {
			return nil, fmt.Errorf("each scope must be between 1 and %d bytes", maxScopeLength)
		}
		// Scopes are space-delimited on the wire, so a scope containing a
		// space would silently become two.
		for _, character := range scope {
			if unicode.IsSpace(character) || unicode.IsControl(character) {
				return nil, fmt.Errorf("scope %q must not contain whitespace or control characters", scope)
			}
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	sort.Strings(normalized)
	return normalized, nil
}

// ValidateClaimName enforces a bounded, printable claim key.
func ValidateClaimName(claim string) error {
	if claim == "" || len(claim) > maxClaimKeyLength {
		return fmt.Errorf("claim name is required and must not exceed %d bytes", maxClaimKeyLength)
	}
	for _, character := range claim {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return fmt.Errorf("claim name %q must not contain whitespace or control characters", claim)
		}
	}
	return nil
}

// ValidateLinking enforces the two modelled linking policies.
func ValidateLinking(linking string) error {
	if linking != LinkingStrict && linking != LinkingVerifiedEmail {
		return fmt.Errorf("linking must be %q or %q", LinkingStrict, LinkingVerifiedEmail)
	}
	return nil
}

// SameOrigin reports whether a URL belongs to the issuer's origin.
//
// This is what stops a hostile discovery document from pointing SESAME's
// token exchange, which carries the client secret, at a server the operator
// never registered. Scheme, host, and port must all match; a subdomain is a
// different origin and is refused.
func SameOrigin(issuer, candidate string) error {
	base, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("issuer is not a valid URL: %w", err)
	}
	target, err := url.Parse(candidate)
	if err != nil {
		return fmt.Errorf("%q is not a valid URL: %w", candidate, err)
	}
	if target.Scheme != "https" {
		return fmt.Errorf("%q must use https", candidate)
	}
	if target.User != nil {
		return fmt.Errorf("%q must not contain userinfo", candidate)
	}
	if !strings.EqualFold(target.Host, base.Host) || target.Scheme != base.Scheme {
		return fmt.Errorf("%q is not on the registered issuer's origin %q", candidate, issuer)
	}
	return nil
}
