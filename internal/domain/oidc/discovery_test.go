package oidc

import (
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/domain/token"
)

// TestAdvertisedCapabilitiesAreTheEnforcedOnes is the point of building the
// discovery document from the validators' own lists: everything published is
// accepted, and nothing outside them is.
func TestAdvertisedCapabilitiesAreTheEnforcedOnes(t *testing.T) {
	t.Parallel()

	metadata, err := BuildMetadata("https://id.example", DefaultEndpoints())
	if err != nil {
		t.Fatalf("BuildMetadata() error = %v", err)
	}

	for _, responseType := range metadata.ResponseTypesSupported {
		if err := ValidateResponseType(responseType); err != nil {
			t.Fatalf("advertised response_type %q is refused: %v", responseType, err)
		}
	}
	for _, grant := range metadata.GrantTypesSupported {
		if err := ValidateGrantType(grant); err != nil {
			t.Fatalf("advertised grant_type %q is refused: %v", grant, err)
		}
	}
	challenge := challengeFor(goodVerifier)
	for _, method := range metadata.CodeChallengeMethodsSupported {
		if err := ValidateCodeChallenge(challenge, method); err != nil {
			t.Fatalf("advertised code_challenge_method %q is refused: %v", method, err)
		}
	}
	for _, scope := range metadata.ScopesSupported {
		if err := ValidateScope(scope); err != nil {
			t.Fatalf("advertised scope %q is refused: %v", scope, err)
		}
	}

	// And the converse: the document does not advertise anything the engine
	// would reject.
	for _, unsupported := range []string{"token", "id_token", "code id_token"} {
		if contains(metadata.ResponseTypesSupported, unsupported) {
			t.Fatalf("the document advertises unsupported response_type %q", unsupported)
		}
	}
	for _, unsupported := range []string{"implicit", "password", "client_credentials"} {
		if contains(metadata.GrantTypesSupported, unsupported) {
			t.Fatalf("the document advertises unsupported grant_type %q", unsupported)
		}
	}
	if contains(metadata.CodeChallengeMethodsSupported, "plain") {
		t.Fatal("the document advertises the plain PKCE method")
	}
	if len(metadata.IDTokenSigningAlgValuesSupported) != 1 ||
		metadata.IDTokenSigningAlgValuesSupported[0] != token.AlgorithmES256 {
		t.Fatalf("advertised signing algorithms = %#v", metadata.IDTokenSigningAlgValuesSupported)
	}
	// "none" as a signing algorithm would be the classic disaster.
	if contains(metadata.IDTokenSigningAlgValuesSupported, "none") ||
		contains(metadata.IDTokenSigningAlgValuesSupported, "HS256") {
		t.Fatal("the document advertises an unsafe signing algorithm")
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func TestBuildMetadataResolvesEndpointsUnderTheIssuer(t *testing.T) {
	t.Parallel()

	metadata, err := BuildMetadata("https://id.example/auth", Endpoints{
		Authorization: "/authorize",
		Token:         "/token",
		JWKS:          "/.well-known/jwks.json",
		Introspection: "https://id.example/auth/introspect",
	})
	if err != nil {
		t.Fatalf("BuildMetadata() error = %v", err)
	}
	if metadata.AuthorizationEndpoint != "https://id.example/auth/authorize" ||
		metadata.TokenEndpoint != "https://id.example/auth/token" ||
		metadata.JWKSURI != "https://id.example/auth/.well-known/jwks.json" ||
		metadata.IntrospectionEndpoint != "https://id.example/auth/introspect" {
		t.Fatalf("metadata = %#v", metadata)
	}
	// An omitted optional endpoint is absent rather than advertised empty.
	if metadata.RevocationEndpoint != "" {
		t.Fatalf("revocation endpoint = %q", metadata.RevocationEndpoint)
	}
}

// TestBuildMetadataRefusesOffOriginEndpoints guards the way a relying party
// gets walked onto an attacker's token endpoint: a discovery document that
// points somewhere else.
func TestBuildMetadataRefusesOffOriginEndpoints(t *testing.T) {
	t.Parallel()

	base := DefaultEndpoints()
	cases := map[string]func(Endpoints) Endpoints{
		"absolute other origin": func(e Endpoints) Endpoints {
			e.Token = "https://evil.example/token"
			return e
		},
		"protocol relative": func(e Endpoints) Endpoints {
			e.Token = "//evil.example/token"
			return e
		},
		"downgraded scheme": func(e Endpoints) Endpoints {
			e.Token = "http://id.example/token"
			return e
		},
		"relative path": func(e Endpoints) Endpoints {
			e.Token = "token"
			return e
		},
		"whitespace": func(e Endpoints) Endpoints {
			e.Token = "/token /evil"
			return e
		},
		"no token endpoint": func(e Endpoints) Endpoints {
			e.Token = ""
			return e
		},
		"no jwks": func(e Endpoints) Endpoints {
			e.JWKS = ""
			return e
		},
	}
	for label, mutate := range cases {
		if _, err := BuildMetadata("https://id.example", mutate(base)); err == nil {
			t.Fatalf("BuildMetadata accepted %s", label)
		}
	}

	for _, issuer := range []string{"", "http://id.example", "not a url", "/relative"} {
		if _, err := BuildMetadata(issuer, base); err == nil {
			t.Fatalf("BuildMetadata accepted issuer %q", issuer)
		}
	}
}

func TestMetadataListsAreCopies(t *testing.T) {
	t.Parallel()

	metadata, err := BuildMetadata("https://id.example", DefaultEndpoints())
	if err != nil {
		t.Fatalf("BuildMetadata() error = %v", err)
	}
	// A caller mutating the published document must not be able to widen
	// what the validators accept.
	metadata.GrantTypesSupported[0] = "password"
	if err := ValidateGrantType("password"); err == nil {
		t.Fatal("mutating the metadata widened the accepted grants")
	}
	if !strings.Contains(strings.Join(SupportedGrantTypes, " "), GrantTypeAuthorizationCode) {
		t.Fatal("mutating the metadata corrupted the supported list")
	}
}
