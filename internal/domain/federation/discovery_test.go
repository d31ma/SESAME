package federation_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d31ma/sesame/internal/domain/federation"
)

func document(t *testing.T, overrides map[string]any) []byte {
	t.Helper()

	base := map[string]any{
		"issuer":                                testIssuer,
		"authorization_endpoint":                testIssuer + "/authorize",
		"token_endpoint":                        testIssuer + "/token",
		"jwks_uri":                              testIssuer + "/jwks",
		"userinfo_endpoint":                     testIssuer + "/userinfo",
		"response_types_supported":              []string{"code"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	for key, value := range overrides {
		if value == nil {
			delete(base, key)
			continue
		}
		base[key] = value
	}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	return raw
}

func TestParseMetadataAcceptsAnHonestDocument(t *testing.T) {
	t.Parallel()

	metadata, err := federation.ParseMetadata(testIssuer, document(t, nil))
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
	if metadata.TokenEndpoint != testIssuer+"/token" {
		t.Fatalf("token endpoint = %q", metadata.TokenEndpoint)
	}
	if metadata.JWKSURI != testIssuer+"/jwks" {
		t.Fatalf("jwks uri = %q", metadata.JWKSURI)
	}
}

// TestParseMetadataRefusesOffOriginEndpoints is the SSRF and credential-theft
// boundary. The token endpoint receives SESAME's client secret and the JWKS
// URI decides which key verifies an assertion, so a document that moves
// either off the registered issuer's origin is refused outright.
func TestParseMetadataRefusesOffOriginEndpoints(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		overrides map[string]any
		want      string
	}{
		{
			name:      "token endpoint on another host",
			overrides: map[string]any{"token_endpoint": "https://evil.example.com/token"},
			want:      "token_endpoint",
		},
		{
			name:      "jwks on another host",
			overrides: map[string]any{"jwks_uri": "https://evil.example.com/jwks"},
			want:      "jwks_uri",
		},
		{
			name:      "authorization endpoint on another host",
			overrides: map[string]any{"authorization_endpoint": "https://evil.example.com/authorize"},
			want:      "authorization_endpoint",
		},
		{
			// A subdomain is a different origin. Attacker-controlled
			// subdomains are common enough that treating them as the same
			// site would give away the whole check.
			name:      "subdomain is not the same origin",
			overrides: map[string]any{"token_endpoint": "https://evil.idp.example.com/token"},
			want:      "token_endpoint",
		},
		{
			// The classic SSRF target: point the host's fetch at itself.
			name:      "loopback",
			overrides: map[string]any{"jwks_uri": "https://127.0.0.1/jwks"},
			want:      "jwks_uri",
		},
		{
			name:      "link-local metadata service",
			overrides: map[string]any{"token_endpoint": "https://169.254.169.254/latest/meta-data"},
			want:      "token_endpoint",
		},
		{
			name:      "scheme downgrade",
			overrides: map[string]any{"token_endpoint": "http://idp.example.com/token"},
			want:      "token_endpoint",
		},
		{
			name:      "credentials in the URL",
			overrides: map[string]any{"token_endpoint": "https://user:pass@idp.example.com/token"},
			want:      "token_endpoint",
		},
		{
			name:      "userinfo off origin",
			overrides: map[string]any{"userinfo_endpoint": "https://evil.example.com/userinfo"},
			want:      "userinfo_endpoint",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := federation.ParseMetadata(testIssuer, document(t, testCase.overrides))
			if err == nil {
				t.Fatal("ParseMetadata accepted an off-origin endpoint")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to name %q", err, testCase.want)
			}
		})
	}
}

// TestParseMetadataRefusesAnIssuerMismatch covers the check that anchors every
// other one.
func TestParseMetadataRefusesAnIssuerMismatch(t *testing.T) {
	t.Parallel()

	_, err := federation.ParseMetadata(testIssuer,
		document(t, map[string]any{"issuer": "https://evil.example.com"}))
	if err == nil {
		t.Fatal("ParseMetadata accepted a document declaring a different issuer")
	}
	if !strings.Contains(err.Error(), "declares issuer") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseMetadataRefusesMalformedDocuments(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		document []byte
		want     string
	}{
		{"empty", nil, "empty"},
		{"not JSON", []byte("<html>a login page</html>"), "not valid JSON"},
		{
			// Two documents concatenated: a sign of a proxy or an injection
			// rather than a provider.
			name:     "trailing data",
			document: append(document(t, nil), []byte(`{"issuer":"https://evil.example.com"}`)...),
			want:     "trailing data",
		},
		{"oversized", make([]byte, federation.MaxDocumentBytes+1), "maximum size"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := federation.ParseMetadata(testIssuer, testCase.document); err == nil {
				t.Fatal("ParseMetadata accepted a malformed document")
			} else if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}

// TestParseMetadataRefusesIncompatibleProviders reports an incompatibility at
// registration rather than as a puzzling failure at someone's first login.
func TestParseMetadataRefusesIncompatibleProviders(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		overrides map[string]any
		want      string
	}{
		{
			name:      "no authorization code support",
			overrides: map[string]any{"response_types_supported": []string{"id_token", "token"}},
			want:      "authorization code",
		},
		{
			name:      "no S256 PKCE",
			overrides: map[string]any{"code_challenge_methods_supported": []string{"plain"}},
			want:      "S256",
		},
		{
			name: "only algorithms SESAME refuses",
			overrides: map[string]any{
				"id_token_signing_alg_values_supported": []string{"HS256", "none"},
			},
			want: "algorithms SESAME does not accept",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := federation.ParseMetadata(testIssuer, document(t, testCase.overrides))
			if err == nil {
				t.Fatal("ParseMetadata accepted an incompatible provider")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}

// TestParseMetadataToleratesOmittedOptionalLists: these are advisory in the
// specification, so absence must not be treated as refusal.
func TestParseMetadataToleratesOmittedOptionalLists(t *testing.T) {
	t.Parallel()

	_, err := federation.ParseMetadata(testIssuer, document(t, map[string]any{
		"response_types_supported":              nil,
		"id_token_signing_alg_values_supported": nil,
		"code_challenge_methods_supported":      nil,
		"userinfo_endpoint":                     nil,
	}))
	if err != nil {
		t.Fatalf("ParseMetadata() error = %v", err)
	}
}

func TestParseKeySetRejectsHostileKeySets(t *testing.T) {
	t.Parallel()

	many := make([]map[string]string, federation.MaxJWKSKeys+1)
	for index := range many {
		many[index] = map[string]string{"kty": "RSA", "kid": string(rune('a' + index))}
	}
	manyJSON, err := json.Marshal(map[string]any{"keys": many})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	cases := []struct {
		name     string
		document []byte
		want     string
	}{
		{"empty", nil, "empty"},
		{"no keys", []byte(`{"keys":[]}`), "no keys"},
		{"too many keys", manyJSON, "more than"},
		{
			// Ambiguous selection between a real key and an attacker's.
			name:     "duplicate kid",
			document: []byte(`{"keys":[{"kty":"RSA","kid":"a"},{"kty":"EC","kid":"a"}]}`),
			want:     "more than once",
		},
		{"trailing data", []byte(`{"keys":[{"kty":"RSA","kid":"a"}]}{"keys":[]}`), "trailing data"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := federation.ParseKeySet(testCase.document); err == nil {
				t.Fatal("ParseKeySet accepted a hostile key set")
			} else if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}
