package oidc

import (
	"strings"
	"testing"
	"time"
)

func TestRefreshIdentifiersAndSecrets(t *testing.T) {
	t.Parallel()

	id, err := NewRefreshID()
	if err != nil {
		t.Fatalf("NewRefreshID() error = %v", err)
	}
	family, err := NewRefreshFamilyID()
	if err != nil {
		t.Fatalf("NewRefreshFamilyID() error = %v", err)
	}
	if err := ValidateRefreshID(id); err != nil {
		t.Fatalf("ValidateRefreshID(%q) = %v", id, err)
	}
	if err := ValidateRefreshFamilyID(family); err != nil {
		t.Fatalf("ValidateRefreshFamilyID(%q) = %v", family, err)
	}
	// The two namespaces do not overlap, so a family ID cannot be presented
	// where a token ID is expected.
	if ValidateRefreshID(family) == nil || ValidateRefreshFamilyID(id) == nil {
		t.Fatal("refresh and family identifiers are interchangeable")
	}
	for _, bad := range []string{"", "rft_", "rfm_", "ses_" + strings.Repeat("0", 32)} {
		if ValidateRefreshID(bad) == nil || ValidateRefreshFamilyID(bad) == nil {
			t.Fatalf("a refresh identifier validator accepted %q", bad)
		}
	}

	secret, digest, err := NewRefreshSecret()
	if err != nil {
		t.Fatalf("NewRefreshSecret() error = %v", err)
	}
	if secret == digest || !VerifyDigest(digest, secret) || VerifyDigest(digest, id) {
		t.Fatalf("secret %q and digest %q", secret, digest)
	}
}

func TestRefreshUsabilityAndFamilyLife(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	token := RefreshToken{ExpiresAt: now.Add(RefreshLifetime).Format(time.RFC3339Nano)}
	if !token.Usable(now) {
		t.Fatal("a fresh refresh token is not usable")
	}
	if token.Usable(now.Add(RefreshLifetime + time.Second)) {
		t.Fatal("an expired refresh token is usable")
	}
	spent := token
	spent.Spent = true
	if spent.Usable(now) {
		t.Fatal("a spent refresh token is usable")
	}
	// An unreadable expiry denies rather than meaning "no bound".
	if (RefreshToken{ExpiresAt: "whenever"}).Usable(now) {
		t.Fatal("a token with an unreadable expiry is usable")
	}

	family := RefreshFamily{ExpiresAt: now.Add(RefreshFamilyLifetime).Format(time.RFC3339Nano)}
	if !family.Live(now) {
		t.Fatal("a fresh family is not live")
	}
	// Rotation must not outlive the absolute ceiling.
	if family.Live(now.Add(RefreshFamilyLifetime + time.Second)) {
		t.Fatal("a family outlived its absolute ceiling")
	}
	revoked := family
	revoked.Revoked = true
	if revoked.Live(now) {
		t.Fatal("a revoked family is live")
	}
}

func TestNarrowScopesNeverWidens(t *testing.T) {
	t.Parallel()

	granted := []string{"openid", "profile", "offline_access"}

	// An empty request keeps what was granted.
	kept, err := NarrowScopes(granted, nil)
	if err != nil || strings.Join(kept, " ") != "openid profile offline_access" {
		t.Fatalf("NarrowScopes(granted, nil) = %#v, %v", kept, err)
	}

	narrowed, err := NarrowScopes(granted, []string{"openid", "openid"})
	if err != nil || strings.Join(narrowed, " ") != "openid" {
		t.Fatalf("NarrowScopes() = %#v, %v", narrowed, err)
	}

	// A refresh keeps a grant alive; it never acquires access the user was
	// not asked about.
	for _, requested := range [][]string{
		{"admin"},
		{"openid", "admin"},
		{"has space"},
	} {
		if _, err := NarrowScopes(granted, requested); err == nil {
			t.Fatalf("NarrowScopes widened to %#v", requested)
		}
	}
}

func TestGrantsOfflineAccess(t *testing.T) {
	t.Parallel()

	if !GrantsOfflineAccess([]string{"openid", "offline_access"}) {
		t.Fatal("GrantsOfflineAccess missed offline_access")
	}
	for _, scopes := range [][]string{nil, {"openid"}, {"openid", "profile"}, {"offline"}} {
		if GrantsOfflineAccess(scopes) {
			t.Fatalf("GrantsOfflineAccess accepted %#v", scopes)
		}
	}
}
