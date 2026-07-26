package oidc

import (
	"strings"
	"testing"
	"time"
)

// TestNewPushedRequestIDIsWellFormedAndDistinct.
func TestNewPushedRequestIDIsWellFormedAndDistinct(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool, 256)
	for range 256 {
		id, err := NewPushedRequestID()
		if err != nil {
			t.Fatalf("NewPushedRequestID() error = %v", err)
		}
		if err := ValidatePushedRequestID(id); err != nil {
			t.Fatalf("NewPushedRequestID() produced %q, which it then rejects: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("NewPushedRequestID() repeated %q", id)
		}
		seen[id] = true
	}
}

// TestParseRequestURIRefusesAnythingButTheExactForm.
//
// This value arrives from a user agent. Being liberal about its shape is how a
// lookup starts accepting things the client never pushed, so every near-miss
// below has to fail rather than be salvaged.
func TestParseRequestURIRefusesAnythingButTheExactForm(t *testing.T) {
	t.Parallel()

	id, err := NewPushedRequestID()
	if err != nil {
		t.Fatalf("NewPushedRequestID() error = %v", err)
	}
	requestURI := RequestURI(id)
	parsed, err := ParseRequestURI(requestURI)
	if err != nil {
		t.Fatalf("ParseRequestURI(%q) error = %v", requestURI, err)
	}
	if parsed != id {
		t.Fatalf("ParseRequestURI() = %q, want %q", parsed, id)
	}

	for name, candidate := range map[string]string{
		"the bare identifier":      id,
		"no identifier":            RequestURIPrefix,
		"a URL that ends in one":   "https://id.example/par/" + id,
		"a prefix that ends in it": "urn:evil:" + RequestURIPrefix + id,
		"traversal":                RequestURIPrefix + "../" + id,
		"a trailing character":     requestURI + "a",
		"a truncated identifier":   requestURI[:len(requestURI)-1],
		"non-hex":                  RequestURIPrefix + PushedRequestIDPrefix + strings.Repeat("z", 32),
		"the wrong prefix":         RequestURIPrefix + "dev_" + strings.Repeat("0", 32),
		"empty":                    "",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseRequestURI(candidate); err == nil {
				t.Fatalf("ParseRequestURI(%q) was accepted", candidate)
			}
		})
	}
}

// TestPushedRequestUsability. A reference is redeemable only while it is both
// unspent and inside its window, and a deadline that cannot be read counts as
// expired rather than as no deadline at all.
func TestPushedRequestUsability(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	live := PushedRequest{ExpiresAt: now.Add(PushedRequestLifetime).Format(time.RFC3339Nano)}

	if !live.Usable(now) {
		t.Fatal("a fresh reference is not usable")
	}
	if live.Usable(now.Add(PushedRequestLifetime)) {
		t.Fatal("a reference outlived its window")
	}

	spent := live
	spent.Consumed = true
	if spent.Usable(now) {
		t.Fatal("a spent reference is still usable")
	}

	for name, expiresAt := range map[string]string{
		"a missing deadline":   "",
		"a malformed deadline": "not-a-timestamp",
		"a unix deadline":      "1700000000",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if (PushedRequest{ExpiresAt: expiresAt}).Usable(now) {
				t.Fatalf("%s was treated as a live reference", name)
			}
		})
	}
}
