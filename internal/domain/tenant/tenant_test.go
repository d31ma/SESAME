package tenant

import (
	"strings"
	"testing"
)

func TestNormalizeAndValidateName(t *testing.T) {
	t.Parallel()

	valid := []string{"acme", "a", "acme-corp-01", "  Acme-Corp  ", "ACME"}
	for _, name := range valid {
		if err := ValidateName(NormalizeName(name)); err != nil {
			t.Fatalf("ValidateName(NormalizeName(%q)) error = %v", name, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"-acme",
		"acme-",
		"acme corp",
		"acme_corp",
		"acmé",
		"acme/../etc",
		strings.Repeat("a", 64),
	}
	for _, name := range invalid {
		if err := ValidateName(NormalizeName(name)); err == nil {
			t.Fatalf("ValidateName(NormalizeName(%q)) accepted an invalid name", name)
		}
	}
}

func TestNewIDIsRandomAndValid(t *testing.T) {
	t.Parallel()

	first, err := NewID()
	if err != nil {
		t.Fatalf("NewID() error = %v", err)
	}
	second, err := NewID()
	if err != nil {
		t.Fatalf("NewID() error = %v", err)
	}
	if first == second {
		t.Fatal("NewID() returned the same value twice")
	}
	for _, id := range []string{first, second} {
		if err := ValidateID(id); err != nil {
			t.Fatalf("ValidateID(%q) error = %v", id, err)
		}
	}

	for _, id := range []string{"", "tnt_", "tnt_zz", "usr_" + strings.Repeat("a", 32), "tnt_" + strings.Repeat("g", 32)} {
		if err := ValidateID(id); err == nil {
			t.Fatalf("ValidateID(%q) accepted an invalid ID", id)
		}
	}
}
