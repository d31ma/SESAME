package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// DiscoveryPath is appended to the registered issuer. SESAME builds this
	// URL itself rather than accepting one, so there is no caller-controlled
	// address for the host to be pointed at.
	DiscoveryPath = "/.well-known/openid-configuration"

	// MaxDocumentBytes bounds any document the host hands back. A provider
	// that needs more than this to describe itself is not one SESAME can
	// safely parse, and an unbounded read is how a hostile endpoint turns a
	// fetch into a memory exhaustion.
	MaxDocumentBytes = 256 * 1024

	// MaxJWKSKeys bounds a key set. Real providers publish a handful; a
	// thousand is an attempt to make signature selection expensive.
	MaxJWKSKeys = 32

	responseTypeCode    = "code"
	challengeMethodS256 = "S256"
)

// ErrDocumentTooLarge is returned when a fetched document exceeds the bound.
var ErrDocumentTooLarge = errors.New("the fetched document exceeds the maximum size")

// Metadata is the subset of an OpenID Provider's discovery document SESAME
// uses. Fields outside this set are ignored rather than stored: SESAME should
// not carry configuration it does not act on.
type Metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	ResponseTypes         []string `json:"response_types_supported,omitempty"`
	SigningAlgorithms     []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ChallengeMethods      []string `json:"code_challenge_methods_supported,omitempty"`
}

// ParseMetadata validates a discovery document against the issuer that was
// registered, and returns only what SESAME will act on.
//
// Everything here is adversarial input. The document is fetched from a server
// that may be compromised or impersonated, so the registered issuer — not the
// document — decides what is acceptable.
func ParseMetadata(issuer string, document []byte) (Metadata, error) {
	if len(document) == 0 {
		return Metadata{}, errors.New("the discovery document is empty")
	}
	if len(document) > MaxDocumentBytes {
		return Metadata{}, ErrDocumentTooLarge
	}

	var metadata Metadata
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	if err := decoder.Decode(&metadata); err != nil {
		return Metadata{}, fmt.Errorf("the discovery document is not valid JSON: %w", err)
	}
	// A second value after the object means the response was not one
	// document, which is a sign of a proxy or an injection rather than a
	// provider.
	if decoder.More() {
		return Metadata{}, errors.New("the discovery document contains trailing data")
	}

	// The issuer must match exactly. This is the check that makes every other
	// check meaningful: without it, a document served at one issuer's URL
	// could describe another issuer's endpoints.
	if metadata.Issuer != issuer {
		return Metadata{}, fmt.Errorf(
			"the discovery document declares issuer %q, but %q is registered",
			metadata.Issuer, issuer)
	}

	if metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" || metadata.JWKSURI == "" {
		return Metadata{}, errors.New(
			"the discovery document must declare authorization_endpoint, token_endpoint, and jwks_uri")
	}
	// Every endpoint has to live on the issuer's own origin. The token
	// endpoint receives SESAME's client secret and the JWKS URI decides which
	// key verifies an assertion; allowing either to move off-origin would let
	// a hostile document redirect a credential or supply its own key.
	for name, endpoint := range map[string]string{
		"authorization_endpoint": metadata.AuthorizationEndpoint,
		"token_endpoint":         metadata.TokenEndpoint,
		"jwks_uri":               metadata.JWKSURI,
	} {
		if err := SameOrigin(issuer, endpoint); err != nil {
			return Metadata{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if metadata.UserInfoEndpoint != "" {
		if err := SameOrigin(issuer, metadata.UserInfoEndpoint); err != nil {
			return Metadata{}, fmt.Errorf("userinfo_endpoint: %w", err)
		}
	}

	// These lists are advisory in the specification, so their absence is not
	// an error. When a provider does declare them, a declaration that
	// excludes what SESAME requires is a real incompatibility and is better
	// reported at registration than as a puzzling failure at login.
	if len(metadata.ResponseTypes) > 0 && !containsFold(metadata.ResponseTypes, responseTypeCode) {
		return Metadata{}, errors.New(
			"the provider does not support the authorization code response type")
	}
	if len(metadata.ChallengeMethods) > 0 && !containsFold(metadata.ChallengeMethods, challengeMethodS256) {
		return Metadata{}, errors.New("the provider does not support the S256 PKCE challenge method")
	}
	if len(metadata.SigningAlgorithms) > 0 {
		usable := false
		for _, algorithm := range metadata.SigningAlgorithms {
			if _, allowed := verificationAlgorithms[algorithm]; allowed {
				usable = true
				break
			}
		}
		if !usable {
			return Metadata{}, fmt.Errorf(
				"the provider signs ID tokens only with algorithms SESAME does not accept: %s",
				strings.Join(metadata.SigningAlgorithms, ", "))
		}
	}
	return metadata, nil
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
