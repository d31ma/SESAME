package oidc

import (
	"strings"
	"testing"
)

// TestRequiresConsentDefaultsToTheStricterRule pins the default that matters:
// a client whose audience was never declared is treated as third party, so an
// omitted field cannot silently exempt exactly the clients most likely to
// need asking.
func TestRequiresConsentDefaultsToTheStricterRule(t *testing.T) {
	t.Parallel()

	if (Client{Audience: AudienceFirstParty}).RequiresConsent() {
		t.Fatal("a first-party client was asked for consent")
	}
	for _, audience := range []string{AudienceThirdParty, "", "unknown", "First_Party"} {
		if !(Client{Audience: audience}).RequiresConsent() {
			t.Fatalf("a client with audience %q skipped consent", audience)
		}
	}

	if err := ValidateAudience(AudienceFirstParty); err != nil {
		t.Fatalf("ValidateAudience(first_party) = %v", err)
	}
	for _, bad := range []string{"", "internal", "First_Party"} {
		if err := ValidateAudience(bad); err == nil {
			t.Fatalf("ValidateAudience accepted %q", bad)
		}
	}
}

func TestConsentCoversOnlyWhatWasAgreed(t *testing.T) {
	t.Parallel()

	consent := Consent{Scopes: []string{"openid", "profile"}}

	if ok, _ := consent.Covers([]string{"openid"}); !ok {
		t.Fatal("consent did not cover an agreed scope")
	}
	if ok, _ := consent.Covers([]string{"openid", "profile"}); !ok {
		t.Fatal("consent did not cover the full agreed set")
	}
	// Asking for more than was agreed needs a fresh decision.
	ok, offending := consent.Covers([]string{"openid", "email"})
	if ok || offending != "email" {
		t.Fatalf("Covers() = %v, %q", ok, offending)
	}

	// A withdrawn consent covers nothing, including what it once covered.
	withdrawn := consent
	withdrawn.Withdrawn = true
	if ok, _ := withdrawn.Covers([]string{"openid"}); ok {
		t.Fatal("a withdrawn consent still covers its scopes")
	}
	// An empty request against a withdrawn consent is still not covered:
	// withdrawal is about the client, not about this particular ask.
	if ok, _ := withdrawn.Covers(nil); ok {
		t.Fatal("a withdrawn consent covered an empty request")
	}
}

func TestMergeScopesKeepsWhatWasAlreadyAgreed(t *testing.T) {
	t.Parallel()

	// Re-consenting to one more scope must not drop the others.
	merged := MergeScopes([]string{"openid", "profile"}, []string{"email"})
	if strings.Join(merged, " ") != "email openid profile" {
		t.Fatalf("MergeScopes() = %#v", merged)
	}
	// Merging is idempotent and does not duplicate.
	again := MergeScopes(merged, []string{"openid", "email"})
	if strings.Join(again, " ") != "email openid profile" {
		t.Fatalf("MergeScopes() = %#v", again)
	}
	// Merging into nothing yields exactly what was granted.
	fresh := MergeScopes(nil, []string{"profile", "openid"})
	if strings.Join(fresh, " ") != "openid profile" {
		t.Fatalf("MergeScopes() = %#v", fresh)
	}
}

func TestValidateConsentScopes(t *testing.T) {
	t.Parallel()

	if err := ValidateConsentScopes([]string{"openid", "profile"}); err != nil {
		t.Fatalf("ValidateConsentScopes() = %v", err)
	}
	if err := ValidateConsentScopes(nil); err == nil {
		t.Fatal("ValidateConsentScopes accepted an empty set")
	}
	if err := ValidateConsentScopes([]string{"has space"}); err == nil {
		t.Fatal("ValidateConsentScopes accepted a malformed scope")
	}
	many := make([]string, maxScopes+1)
	for index := range many {
		many[index] = "scope" + string(rune('a'+index%26))
	}
	if err := ValidateConsentScopes(many); err == nil {
		t.Fatal("ValidateConsentScopes accepted an unbounded set")
	}
}
