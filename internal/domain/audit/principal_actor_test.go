package audit

import (
	"errors"
	"testing"
)

func TestPrincipalActorRoundTripsThroughItsRecordedText(t *testing.T) {
	t.Parallel()

	actor := PrincipalActor{
		TenantID:    "tnt_0123456789abcdef0123456789abcdef",
		PrincipalID: "prn_0123456789abcdef0123456789abcdef",
		SessionID:   "ses_0123456789abcdef0123456789abcdef",
	}
	text := actor.String()
	want := "principal:tnt_0123456789abcdef0123456789abcdef/prn_0123456789abcdef0123456789abcdef/ses_0123456789abcdef0123456789abcdef"
	if text != want {
		t.Fatalf("String() = %q, want %q", text, want)
	}
	if !IsPrincipalActor(text) {
		t.Fatal("IsPrincipalActor() = false for a principal actor")
	}
	parsed, err := ParsePrincipalActor(text)
	if err != nil || parsed != actor {
		t.Fatalf("ParsePrincipalActor() = %#v, %v", parsed, err)
	}
}

func TestOperatorActorsAreNotPrincipalActors(t *testing.T) {
	t.Parallel()

	for _, text := range []string{"operator:machine", "operator:cli", "", "principal"} {
		if IsPrincipalActor(text) {
			t.Fatalf("IsPrincipalActor(%q) = true", text)
		}
		if _, err := ParsePrincipalActor(text); !errors.Is(err, ErrMalformedPrincipalActor) {
			t.Fatalf("ParsePrincipalActor(%q) error = %v", text, err)
		}
	}
}

func TestMalformedPrincipalActorTextIsRefused(t *testing.T) {
	t.Parallel()

	for _, text := range []string{
		"principal:",
		"principal:tnt_a/prn_b",
		"principal:tnt_a/prn_b/ses_c/extra",
	} {
		if _, err := ParsePrincipalActor(text); !errors.Is(err, ErrMalformedPrincipalActor) {
			t.Fatalf("ParsePrincipalActor(%q) error = %v, want malformed", text, err)
		}
	}
}
