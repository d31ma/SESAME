package authorization

import (
	"strings"
	"testing"
)

func TestValidatePattern(t *testing.T) {
	t.Parallel()

	valid := []string{"doc:read", "doc:*", "*", "billing.invoice:write", "a:b:c", "a_b-c.d"}
	for _, pattern := range valid {
		if err := ValidatePattern(pattern); err != nil {
			t.Fatalf("ValidatePattern(%q) error = %v", pattern, err)
		}
	}
	invalid := []string{
		"",
		"Doc:read",
		"doc:*:read",
		"doc:",
		":read",
		"doc read",
		"doc:re*d",
		strings.Repeat("a", 129),
	}
	for _, pattern := range invalid {
		if err := ValidatePattern(pattern); err == nil {
			t.Fatalf("ValidatePattern(%q) accepted an invalid pattern", pattern)
		}
	}

	if err := ValidateValue("doc:read"); err != nil {
		t.Fatalf("ValidateValue(doc:read) error = %v", err)
	}
	for _, value := range []string{"doc:*", "*"} {
		if err := ValidateValue(value); err == nil {
			t.Fatalf("ValidateValue(%q) accepted a wildcard", value)
		}
	}
}

func TestMatchesIsDeterministic(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"doc:read", "doc:read", true},
		{"doc:read", "doc:write", false},
		{"doc:read", "doc:read:extra", false},
		{"doc:*", "doc:read", true},
		{"doc:*", "doc:read:extra", true},
		{"doc:*", "doc", false},
		{"doc:*", "documents:read", false},
		{"*", "anything", true},
		{"*", "a:b:c", true},
		{"a:b", "a", false},
	}
	for _, test := range cases {
		if got := Matches(test.pattern, test.value); got != test.want {
			t.Fatalf("Matches(%q, %q) = %t, want %t", test.pattern, test.value, got, test.want)
		}
	}
}

func TestValidatePermissions(t *testing.T) {
	t.Parallel()

	if err := ValidatePermissions([]Permission{{Action: "doc:read", Resource: "project:*"}}); err != nil {
		t.Fatalf("ValidatePermissions(valid) error = %v", err)
	}
	if err := ValidatePermissions(nil); err == nil {
		t.Fatal("ValidatePermissions(empty) accepted an empty set")
	}
	if err := ValidatePermissions([]Permission{{Action: "BAD", Resource: "*"}}); err == nil {
		t.Fatal("ValidatePermissions accepted an invalid action")
	}
	oversized := make([]Permission, 65)
	for index := range oversized {
		oversized[index] = Permission{Action: "doc:read", Resource: "*"}
	}
	if err := ValidatePermissions(oversized); err == nil {
		t.Fatal("ValidatePermissions accepted an oversized set")
	}
}

func TestIDs(t *testing.T) {
	t.Parallel()

	roleID, err := NewRoleID()
	if err != nil || ValidateRoleID(roleID) != nil {
		t.Fatalf("NewRoleID() = %q, %v", roleID, err)
	}
	grantID, err := NewGrantID()
	if err != nil || ValidateGrantID(grantID) != nil {
		t.Fatalf("NewGrantID() = %q, %v", grantID, err)
	}
	if ValidateRoleID(grantID) == nil || ValidateGrantID(roleID) == nil {
		t.Fatal("ID validation accepted a mismatched prefix")
	}
}
