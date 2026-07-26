package oidc

import (
	"strings"
	"testing"
)

func TestValidateRedirectURIRejectsUnsafeShapes(t *testing.T) {
	t.Parallel()

	accepted := []string{
		"https://app.example/callback",
		"https://app.example/callback?tenant=acme",
		"https://app.example:8443/callback",
		"http://127.0.0.1:8080/callback",
		"http://localhost:3000/cb",
		"http://[::1]:9000/cb",
	}
	for _, uri := range accepted {
		if err := ValidateRedirectURI(uri); err != nil {
			t.Fatalf("ValidateRedirectURI(%q) = %v, want nil", uri, err)
		}
	}

	rejected := map[string]string{
		"empty":            "",
		"relative":         "/callback",
		"plain http":       "http://app.example/callback",
		"wildcard host":    "https://*.example/callback",
		"wildcard path":    "https://app.example/*",
		"fragment":         "https://app.example/callback#code",
		"javascript":       "javascript:alert(1)",
		"data":             "data:text/html,x",
		"private scheme":   "com.example.app:/callback",
		"no host":          "https:///callback",
		"embedded space":   "https://app.example/cb evil",
		"embedded newline": "https://app.example/cb\nLocation: https://evil.example",
	}
	for name, uri := range rejected {
		if err := ValidateRedirectURI(uri); err == nil {
			t.Fatalf("ValidateRedirectURI accepted %s (%q)", name, uri)
		}
	}

	long := "https://app.example/" + strings.Repeat("a", maxRedirectURILength)
	if err := ValidateRedirectURI(long); err == nil {
		t.Fatal("ValidateRedirectURI accepted an oversized URI")
	}
}

func TestRedirectMatchingIsExact(t *testing.T) {
	t.Parallel()

	registered, err := NormalizeRedirectURIs([]string{
		"https://app.example/cb",
		"https://app.example/cb",
		"https://admin.example/cb",
	})
	if err != nil {
		t.Fatalf("NormalizeRedirectURIs() error = %v", err)
	}
	// Duplicates collapse and the order is canonical, so one registration
	// always stores identically.
	if len(registered) != 2 || registered[0] != "https://admin.example/cb" {
		t.Fatalf("registered = %#v", registered)
	}

	if !MatchRedirectURI(registered, "https://app.example/cb") {
		t.Fatal("MatchRedirectURI rejected a registered URI")
	}
	// Every one of these is a real-world open-redirect attempt against a
	// prefix or suffix matcher.
	for _, requested := range []string{
		"https://app.example/cb/",
		"https://app.example/cb/../evil",
		"https://app.example/cb?next=https://evil.example",
		"https://app.example/cb#x",
		"https://app.example.evil/cb",
		"https://evil.example/https://app.example/cb",
		"HTTPS://APP.EXAMPLE/cb",
		"",
	} {
		if MatchRedirectURI(registered, requested) {
			t.Fatalf("MatchRedirectURI accepted %q", requested)
		}
	}
}

func TestNormalizeRedirectURIsBounds(t *testing.T) {
	t.Parallel()

	if _, err := NormalizeRedirectURIs(nil); err == nil {
		t.Fatal("NormalizeRedirectURIs accepted an empty set")
	}
	many := make([]string, maxRedirectURIs+1)
	for index := range many {
		many[index] = "https://app.example/cb" + string(rune('a'+index%26)) + string(rune('0'+index/26))
	}
	if _, err := NormalizeRedirectURIs(many); err == nil {
		t.Fatal("NormalizeRedirectURIs accepted an unbounded set")
	}
}

func TestNormalizeScopesAlwaysIncludesOpenID(t *testing.T) {
	t.Parallel()

	scopes, err := NormalizeScopes([]string{"profile", "profile", "email"})
	if err != nil {
		t.Fatalf("NormalizeScopes() error = %v", err)
	}
	if strings.Join(scopes, " ") != "email openid profile" {
		t.Fatalf("scopes = %#v", scopes)
	}

	for _, bad := range []string{"", "has space", "has\"quote", "has\\slash", strings.Repeat("s", maxScopeLength+1)} {
		if _, err := NormalizeScopes([]string{bad}); err == nil {
			t.Fatalf("NormalizeScopes accepted %q", bad)
		}
	}
}

func TestAllowsScopesNamesTheOffender(t *testing.T) {
	t.Parallel()

	client := Client{Scopes: []string{"email", "openid"}}
	if ok, _ := client.AllowsScopes([]string{"openid", "email"}); !ok {
		t.Fatal("AllowsScopes rejected registered scopes")
	}
	ok, offending := client.AllowsScopes([]string{"openid", "admin"})
	if ok || offending != "admin" {
		t.Fatalf("AllowsScopes() = %v, %q", ok, offending)
	}
}

func TestClientIdentifiersAndSecrets(t *testing.T) {
	t.Parallel()

	id, err := NewClientID()
	if err != nil {
		t.Fatalf("NewClientID() error = %v", err)
	}
	if err := ValidateClientID(id); err != nil {
		t.Fatalf("ValidateClientID(%q) = %v", id, err)
	}
	for _, bad := range []string{"", "cli_", "rol_" + strings.Repeat("0", 32), "cli_" + strings.Repeat("z", 32)} {
		if err := ValidateClientID(bad); err == nil {
			t.Fatalf("ValidateClientID accepted %q", bad)
		}
	}

	first, err := NewClientSecret()
	if err != nil {
		t.Fatalf("NewClientSecret() error = %v", err)
	}
	second, _ := NewClientSecret()
	if first == second || len(first) != clientSecretRandBytes*2 {
		t.Fatalf("client secrets are not fresh high-entropy values: %q %q", first, second)
	}

	if err := ValidateType("public"); err != nil {
		t.Fatalf("ValidateType(public) = %v", err)
	}
	for _, bad := range []string{"", "native", "Confidential"} {
		if err := ValidateType(bad); err == nil {
			t.Fatalf("ValidateType accepted %q", bad)
		}
	}
	if err := ValidateName(""); err == nil {
		t.Fatal("ValidateName accepted an empty name")
	}
	if err := ValidateName("bad\x00name"); err == nil {
		t.Fatal("ValidateName accepted a control character")
	}
}
