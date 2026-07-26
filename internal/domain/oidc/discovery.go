// Discovery metadata.
//
// The lists below are the single source of truth for what SESAME accepts.
// The validators in this package read them, and the published document is
// built from them, so an advertised capability is by construction one the
// engine actually implements. A hand-written metadata document is a promise
// nothing enforces; this one cannot drift.
package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Supported capabilities. Adding a value here is not enough to implement it —
// but removing a value here does stop it being accepted, because the
// validators read these lists.
var (
	// SupportedResponseTypes excludes the implicit and hybrid flows, which
	// return tokens through the front channel.
	SupportedResponseTypes = []string{ResponseTypeCode}
	// SupportedGrantTypes excludes the implicit and resource-owner-password
	// grants, which are not modelled at all.
	SupportedGrantTypes = []string{
		GrantTypeAuthorizationCode,
		GrantTypeRefreshToken,
		GrantTypeDeviceCode,
	}
	// SupportedChallengeMethods excludes "plain", which carries the verifier
	// in the authorization request and so defeats the exchange.
	SupportedChallengeMethods = []string{ChallengeMethodS256}
	// SupportedSigningAlgorithms is one algorithm on purpose: nothing is
	// negotiated, so nothing can be confused.
	SupportedSigningAlgorithms = []string{AlgorithmES256}
	// SupportedClientAuthMethods covers a confidential client presenting its
	// secret, and a public client presenting nothing but PKCE.
	SupportedClientAuthMethods = []string{"client_secret_basic", "client_secret_post", "none"}
	// SupportedSubjectTypes is public: SESAME's subject is the principal ID,
	// which is already opaque and carries no personal data.
	SupportedSubjectTypes = []string{"public"}
	// SupportedScopes is what every client may request; a client's own
	// registration narrows it further.
	SupportedScopes = []string{ScopeOpenID, "profile", "email", ScopeOfflineAccess}
)

// AlgorithmES256 mirrors the token package's constant. The two are asserted
// equal by test rather than imported, so the discovery document does not drag
// signing-key machinery into the domain.
const AlgorithmES256 = "ES256"

// Endpoints are the host's own route paths. SESAME owns no listener, so the
// host says where its routes live and the engine turns them into absolute
// URLs under the configured issuer.
type Endpoints struct {
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	JWKS          string `json:"jwks_uri"`
	Introspection string `json:"introspection_endpoint,omitempty"`
	Revocation    string `json:"revocation_endpoint,omitempty"`
	EndSession    string `json:"end_session_endpoint,omitempty"`
}

// DefaultEndpoints are the conventional paths, used when a host does not name
// its own.
func DefaultEndpoints() Endpoints {
	return Endpoints{
		Authorization: "/authorize",
		Token:         "/token",
		JWKS:          "/.well-known/jwks.json",
		Introspection: "/introspect",
		Revocation:    "/revoke",
		EndSession:    "/logout",
	}
}

// Metadata is the published OpenID provider configuration.
type Metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	// RequirePKCE is not a registered metadata field, but a client library
	// reading this document should know PKCE is mandatory rather than
	// discovering it from a rejection.
	RequirePKCE bool `json:"require_pushed_authorization_requests,omitempty"`
}

// BuildMetadata composes the discovery document for one issuer.
//
// Every endpoint must resolve under the issuer's own origin. A discovery
// document that points a client at another origin is how a relying party gets
// walked onto an attacker's token endpoint, so an off-origin path is refused
// rather than published.
func BuildMetadata(issuer string, endpoints Endpoints) (Metadata, error) {
	if issuer == "" {
		return Metadata{}, errors.New("issuer is required")
	}
	base, err := url.Parse(issuer)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return Metadata{}, fmt.Errorf("issuer %q must be an absolute https URL", issuer)
	}

	resolve := func(path, label string) (string, error) {
		if path == "" {
			return "", nil
		}
		absolute, err := resolveEndpoint(base, path)
		if err != nil {
			return "", fmt.Errorf("%s: %w", label, err)
		}
		return absolute, nil
	}

	authorization, err := resolve(endpoints.Authorization, "authorization_endpoint")
	if err != nil {
		return Metadata{}, err
	}
	tokenEndpoint, err := resolve(endpoints.Token, "token_endpoint")
	if err != nil {
		return Metadata{}, err
	}
	jwks, err := resolve(endpoints.JWKS, "jwks_uri")
	if err != nil {
		return Metadata{}, err
	}
	introspection, err := resolve(endpoints.Introspection, "introspection_endpoint")
	if err != nil {
		return Metadata{}, err
	}
	revocation, err := resolve(endpoints.Revocation, "revocation_endpoint")
	if err != nil {
		return Metadata{}, err
	}
	endSession, err := resolve(endpoints.EndSession, "end_session_endpoint")
	if err != nil {
		return Metadata{}, err
	}
	if authorization == "" || tokenEndpoint == "" || jwks == "" {
		return Metadata{}, errors.New("authorization, token, and JWKS endpoints are required")
	}

	return Metadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             authorization,
		TokenEndpoint:                     tokenEndpoint,
		JWKSURI:                           jwks,
		IntrospectionEndpoint:             introspection,
		RevocationEndpoint:                revocation,
		EndSessionEndpoint:                endSession,
		ScopesSupported:                   slices.Clone(SupportedScopes),
		ResponseTypesSupported:            slices.Clone(SupportedResponseTypes),
		GrantTypesSupported:               slices.Clone(SupportedGrantTypes),
		SubjectTypesSupported:             slices.Clone(SupportedSubjectTypes),
		IDTokenSigningAlgValuesSupported:  slices.Clone(SupportedSigningAlgorithms),
		CodeChallengeMethodsSupported:     slices.Clone(SupportedChallengeMethods),
		TokenEndpointAuthMethodsSupported: slices.Clone(SupportedClientAuthMethods),
		ClaimsSupported: []string{
			"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "sid", "acr", "nonce", "tenant_id",
		},
	}, nil
}

// resolveEndpoint turns a host route path into an absolute URL under the
// issuer, refusing anything that would leave the issuer's origin.
func resolveEndpoint(base *url.URL, path string) (string, error) {
	if strings.ContainsAny(path, " \t\r\n") {
		return "", errors.New("endpoint path must not contain whitespace")
	}
	parsed, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("endpoint %q is not a valid URL", path)
	}
	// A caller may supply a complete URL, but only its own issuer's.
	if parsed.IsAbs() {
		if parsed.Scheme != base.Scheme || parsed.Host != base.Host {
			return "", fmt.Errorf("endpoint %q is not under the issuer origin", path)
		}
		return parsed.String(), nil
	}
	if parsed.Host != "" {
		// A protocol-relative "//host/path" would silently change origin.
		return "", fmt.Errorf("endpoint %q is not under the issuer origin", path)
	}
	if !strings.HasPrefix(parsed.Path, "/") {
		return "", fmt.Errorf("endpoint %q must be an absolute path", path)
	}
	resolved := *base
	resolved.Path = base.Path + parsed.Path
	resolved.RawQuery = parsed.RawQuery
	resolved.Fragment = ""
	return resolved.String(), nil
}
