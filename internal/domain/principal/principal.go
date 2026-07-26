// Package principal defines human and workload identities and their
// normalized identifiers.
package principal

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	// KindHuman is an interactive person.
	KindHuman = "human"
	// KindWorkload is a non-interactive service identity.
	KindWorkload = "workload"

	// StatusActive permits authentication and authorization.
	StatusActive = "active"
	// StatusSuspended is a durable, replayable deny state.
	StatusSuspended = "suspended"

	// EventCreated records a principal and its first identifier claim as one
	// atomic security event.
	EventCreated = "principal.created"
	// EventSuspended records a durable suspension.
	EventSuspended = "principal.suspended"

	// IDPrefix distinguishes principal identifiers from other public IDs.
	IDPrefix = "prn_"

	maxIdentifierLength = 254
	maxNamespaceLength  = 32
)

// Principal is one human or workload identity inside a tenant.
type Principal struct {
	ID         string     `json:"principal_id"`
	TenantID   string     `json:"tenant_id"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	Identifier Identifier `json:"identifier"`
}

// Identifier locates a principal inside one tenant-scoped namespace. It is
// not a credential.
type Identifier struct {
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
}

// CreatedPayload is the versioned payload of an EventCreated event.
type CreatedPayload struct {
	PrincipalID         string `json:"principal_id"`
	TenantID            string `json:"tenant_id"`
	Kind                string `json:"kind"`
	Status              string `json:"status"`
	IdentifierNamespace string `json:"identifier_namespace"`
	IdentifierValue     string `json:"identifier_value"`
}

// SuspendedPayload is the versioned payload of an EventSuspended event.
type SuspendedPayload struct {
	PrincipalID string `json:"principal_id"`
	TenantID    string `json:"tenant_id"`
}

// ValidateKind rejects unknown principal kinds.
func ValidateKind(kind string) error {
	if kind != KindHuman && kind != KindWorkload {
		return fmt.Errorf("principal kind must be %q or %q", KindHuman, KindWorkload)
	}
	return nil
}

// NormalizeIdentifier lowercases and trims an identifier value so uniqueness
// checks are deterministic.
func NormalizeIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// ValidateIdentifier enforces the bounded shape of a normalized identifier.
func ValidateIdentifier(identifier Identifier) error {
	if identifier.Namespace == "" || len(identifier.Namespace) > maxNamespaceLength {
		return fmt.Errorf(
			"identifier namespace is required and must not exceed %d bytes",
			maxNamespaceLength,
		)
	}
	for _, character := range identifier.Namespace {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '-':
		default:
			return fmt.Errorf("identifier namespace contains unsupported character %q", character)
		}
	}
	if identifier.Value == "" {
		return errors.New("identifier value is required")
	}
	if len(identifier.Value) > maxIdentifierLength {
		return fmt.Errorf("identifier value must not exceed %d bytes", maxIdentifierLength)
	}
	for _, character := range identifier.Value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return errors.New("identifier value must not contain whitespace or control characters")
		}
		if unicode.IsUpper(character) {
			return errors.New("identifier value must be normalized to lower case")
		}
	}
	return nil
}

// NewID returns a random public principal identifier.
func NewID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate principal ID: %w", err)
	}
	return IDPrefix + hex.EncodeToString(value), nil
}

// ValidateID rejects values that cannot be SESAME principal identifiers.
func ValidateID(id string) error {
	if !strings.HasPrefix(id, IDPrefix) || len(id) != len(IDPrefix)+32 {
		return errors.New("principal ID must be prn_ followed by 32 hex characters")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, IDPrefix)); err != nil {
		return errors.New("principal ID must be prn_ followed by 32 hex characters")
	}
	return nil
}
