package principal

import (
	"strings"
	"testing"
)

func TestValidateKind(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{KindHuman, KindWorkload} {
		if err := ValidateKind(kind); err != nil {
			t.Fatalf("ValidateKind(%q) error = %v", kind, err)
		}
	}
	for _, kind := range []string{"", "robot", "HUMAN"} {
		if err := ValidateKind(kind); err == nil {
			t.Fatalf("ValidateKind(%q) accepted an invalid kind", kind)
		}
	}
}

func TestNormalizeAndValidateIdentifier(t *testing.T) {
	t.Parallel()

	valid := []Identifier{
		{Namespace: "email", Value: NormalizeIdentifier("  Alice@Example.COM ")},
		{Namespace: "login", Value: "alice"},
		{Namespace: "external-oidc", Value: "sub|1234"},
	}
	for _, identifier := range valid {
		if err := ValidateIdentifier(identifier); err != nil {
			t.Fatalf("ValidateIdentifier(%#v) error = %v", identifier, err)
		}
	}

	invalid := []Identifier{
		{Namespace: "", Value: "alice"},
		{Namespace: "Email", Value: "alice"},
		{Namespace: "email", Value: ""},
		{Namespace: "email", Value: "Alice"},
		{Namespace: "email", Value: "a lice"},
		{Namespace: "email", Value: "alice\n"},
		{Namespace: "email", Value: strings.Repeat("a", 255)},
		{Namespace: strings.Repeat("n", 33), Value: "alice"},
	}
	for _, identifier := range invalid {
		if err := ValidateIdentifier(identifier); err == nil {
			t.Fatalf("ValidateIdentifier(%#v) accepted an invalid identifier", identifier)
		}
	}
}

func TestIDGeneration(t *testing.T) {
	t.Parallel()

	first, err := NewID()
	if err != nil || ValidateID(first) != nil {
		t.Fatalf("NewID() = %q, %v", first, err)
	}
	second, _ := NewID()
	if first == second {
		t.Fatal("NewID() returned the same value twice")
	}
	for _, id := range []string{"", "prn_", "tnt_" + strings.Repeat("a", 32), "prn_" + strings.Repeat("g", 32)} {
		if err := ValidateID(id); err == nil {
			t.Fatalf("ValidateID(%q) accepted an invalid ID", id)
		}
	}
}
