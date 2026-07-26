package federation_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/d31ma/sesame/internal/domain/federation"
)

// TestNormalizeIssuerRefusesUnsafeIssuers covers the trust anchor. Everything
// else in federation is checked against the issuer, so a weak issuer weakens
// every later check.
func TestNormalizeIssuerRefusesUnsafeIssuers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		issuer string
		want   string
	}{
		{"empty", "", "required"},
		{"plaintext", "http://idp.example.com", "https"},
		{"no host", "https://", "host"},
		{"credentials", "https://user:pass@idp.example.com", "userinfo"},
		{"query", "https://idp.example.com?tenant=1", "query or fragment"},
		{"fragment", "https://idp.example.com#x", "query or fragment"},
		{
			// Trimming would make SESAME accept an `iss` the provider never
			// sends, because OpenID Connect compares it byte for byte.
			name:   "trailing slash",
			issuer: "https://idp.example.com/",
			want:   "trailing slash",
		},
		{"leading whitespace", " https://idp.example.com", "whitespace"},
		{"embedded newline", "https://idp.example.com\n", "whitespace"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := federation.NormalizeIssuer(testCase.issuer); err == nil {
				t.Fatal("NormalizeIssuer accepted an unsafe issuer")
			} else if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}

	// A path-bearing issuer is legitimate and common with multi-tenant
	// providers, so it must survive.
	issuer, err := federation.NormalizeIssuer("https://login.example.com/tenants/acme")
	if err != nil {
		t.Fatalf("NormalizeIssuer() error = %v", err)
	}
	if issuer != "https://login.example.com/tenants/acme" {
		t.Fatalf("issuer = %q, want it unchanged", issuer)
	}
}

func TestNormalizeScopesAlwaysIncludesOpenID(t *testing.T) {
	t.Parallel()

	// Without openid the provider returns no ID token, and SESAME has nothing
	// to verify. Callers should not be able to configure that away.
	scopes, err := federation.NormalizeScopes(nil)
	if err != nil {
		t.Fatalf("NormalizeScopes() error = %v", err)
	}
	if len(scopes) != 1 || scopes[0] != federation.ScopeOpenID {
		t.Fatalf("scopes = %v, want just openid", scopes)
	}

	scopes, err = federation.NormalizeScopes([]string{"profile", "email", "profile"})
	if err != nil {
		t.Fatalf("NormalizeScopes() error = %v", err)
	}
	want := []string{"email", "openid", "profile"}
	if len(scopes) != len(want) {
		t.Fatalf("scopes = %v, want %v", scopes, want)
	}
	for index, scope := range want {
		if scopes[index] != scope {
			t.Fatalf("scopes = %v, want %v (sorted and deduplicated)", scopes, want)
		}
	}

	// Scopes are space-delimited on the wire, so an embedded space would
	// silently become two scopes.
	if _, err := federation.NormalizeScopes([]string{"profile email"}); err == nil {
		t.Fatal("NormalizeScopes accepted a scope containing a space")
	}
}

func TestSameOriginComparesSchemeHostAndPort(t *testing.T) {
	t.Parallel()

	issuer := "https://idp.example.com"
	if err := federation.SameOrigin(issuer, issuer+"/token"); err != nil {
		t.Fatalf("SameOrigin() rejected the issuer's own path: %v", err)
	}
	// A non-default port is a different origin.
	if err := federation.SameOrigin(issuer, "https://idp.example.com:8443/token"); err == nil {
		t.Fatal("SameOrigin accepted a different port")
	}
	// Host comparison is case-insensitive, because DNS is.
	if err := federation.SameOrigin(issuer, "https://IDP.EXAMPLE.COM/token"); err != nil {
		t.Fatalf("SameOrigin() rejected a case difference in the host: %v", err)
	}
}

func TestValidateLinkingAndClaimNames(t *testing.T) {
	t.Parallel()

	if err := federation.ValidateLinking("anything-goes"); err == nil {
		t.Fatal("ValidateLinking accepted an unmodelled policy")
	}
	for _, linking := range []string{federation.LinkingStrict, federation.LinkingVerifiedEmail} {
		if err := federation.ValidateLinking(linking); err != nil {
			t.Fatalf("ValidateLinking(%q) error = %v", linking, err)
		}
	}
	if err := federation.ValidateClaimName("email address"); err == nil {
		t.Fatal("ValidateClaimName accepted a claim name containing a space")
	}
	if err := federation.ValidateClaimName("email"); err != nil {
		t.Fatalf("ValidateClaimName() error = %v", err)
	}
}

func TestProviderIdentifiersRoundTrip(t *testing.T) {
	t.Parallel()

	id, err := federation.NewProviderID()
	if err != nil {
		t.Fatalf("NewProviderID() error = %v", err)
	}
	if err := federation.ValidateProviderID(id); err != nil {
		t.Fatalf("ValidateProviderID(%q) error = %v", id, err)
	}
	for _, bad := range []string{"", "idp_", "cli_" + strings.Repeat("a", 32), "idp_zzzz"} {
		if err := federation.ValidateProviderID(bad); err == nil {
			t.Fatalf("ValidateProviderID(%q) accepted a malformed identifier", bad)
		}
	}
}

// TestSubjectHashSeparatesProviders: the same subject string at two providers
// is two different people, and collapsing them would let one provider assert
// another's users.
func TestSubjectHashSeparatesProviders(t *testing.T) {
	t.Parallel()

	first := federation.SubjectHash("idp_aaaa", "user-1")
	second := federation.SubjectHash("idp_bbbb", "user-1")
	if first == second {
		t.Fatal("the same subject at two providers hashes identically")
	}
	if first != federation.SubjectHash("idp_aaaa", "user-1") {
		t.Fatal("SubjectHash is not deterministic")
	}
	// The separator must not be forgeable by a subject that contains it.
	if federation.SubjectHash("idp_a", "b\x00c") == federation.SubjectHash("idp_a\x00b", "c") {
		t.Fatal("provider and subject can be shifted across the separator")
	}
}

func TestChallengeMatchesTheS256Definition(t *testing.T) {
	t.Parallel()

	// The known vector from RFC 7636 appendix B.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := federation.Challenge(verifier); got != want {
		t.Fatalf("Challenge() = %q, want %q", got, want)
	}
}

func TestMatchStateRejectsAMismatch(t *testing.T) {
	t.Parallel()

	state, err := federation.NewState()
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	digest := federation.Digest(state)
	if !federation.MatchState(state, digest) {
		t.Fatal("MatchState rejected the state it stored")
	}
	if federation.MatchState("a-forged-state", digest) {
		t.Fatal("MatchState accepted a forged state")
	}
	if federation.MatchState("", digest) {
		t.Fatal("MatchState accepted an empty state")
	}
}

// TestLoginUsable covers the single-use and expiry rules that stop a
// provider's authorization code from minting a second session.
func TestLoginUsable(t *testing.T) {
	t.Parallel()

	now := time.Now()
	pending := federation.Login{
		Status:    federation.LoginPending,
		ExpiresAt: now.Add(federation.LoginLifetime),
	}
	if err := pending.Usable(now); err != nil {
		t.Fatalf("a fresh pending login is unusable: %v", err)
	}

	spent := pending
	spent.Status = federation.LoginCompleted
	if err := spent.Usable(now); !errors.Is(err, federation.ErrLoginNotPending) {
		t.Fatalf("error = %v, want ErrLoginNotPending", err)
	}

	failed := pending
	failed.Status = federation.LoginFailed
	if err := failed.Usable(now); !errors.Is(err, federation.ErrLoginNotPending) {
		t.Fatalf("error = %v, want ErrLoginNotPending", err)
	}

	expired := pending
	expired.ExpiresAt = now.Add(-time.Second)
	if err := expired.Usable(now); !errors.Is(err, federation.ErrLoginExpired) {
		t.Fatalf("error = %v, want ErrLoginExpired", err)
	}

	// Expiry is reported ahead of status, because "expired" is the more
	// useful diagnosis for a transaction that is both.
	both := expired
	both.Status = federation.LoginCompleted
	if err := both.Usable(now); !errors.Is(err, federation.ErrLoginExpired) {
		t.Fatalf("error = %v, want ErrLoginExpired to take precedence", err)
	}
}

func TestSecretsAreDistinctAndHighEntropy(t *testing.T) {
	t.Parallel()

	state, err := federation.NewState()
	if err != nil {
		t.Fatalf("NewState() error = %v", err)
	}
	nonce, err := federation.NewNonce()
	if err != nil {
		t.Fatalf("NewNonce() error = %v", err)
	}
	verifier, err := federation.NewVerifier()
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	if state == nonce || nonce == verifier || state == verifier {
		t.Fatal("two federated login secrets came out equal")
	}
	// 32 random bytes, base64url without padding.
	for name, secret := range map[string]string{"state": state, "nonce": nonce, "verifier": verifier} {
		if len(secret) < 43 {
			t.Fatalf("%s is %d characters, too short for 32 random bytes", name, len(secret))
		}
		if strings.ContainsAny(secret, "+/=") {
			t.Fatalf("%s is not URL-safe: %q", name, secret)
		}
	}
}

func TestValidateNameRejectsControlCharacters(t *testing.T) {
	t.Parallel()

	if err := federation.ValidateName(""); err == nil {
		t.Fatal("ValidateName accepted an empty name")
	}
	if err := federation.ValidateName("Corp SSO\x07"); err == nil {
		t.Fatal("ValidateName accepted a control character")
	}
	if err := federation.ValidateName("Corp SSO"); err != nil {
		t.Fatalf("ValidateName() error = %v", err)
	}
}

func TestLoginIdentifiersRoundTrip(t *testing.T) {
	t.Parallel()

	id, err := federation.NewLoginID()
	if err != nil {
		t.Fatalf("NewLoginID() error = %v", err)
	}
	if err := federation.ValidateLoginID(id); err != nil {
		t.Fatalf("ValidateLoginID(%q) error = %v", id, err)
	}
	if err := federation.ValidateLoginID("idp_" + strings.Repeat("a", 32)); err == nil {
		t.Fatal("ValidateLoginID accepted a provider identifier")
	}
}
