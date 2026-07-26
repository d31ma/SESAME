// Package tenant defines the tenant identity domain model.
package tenant

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// StatusActive is the only tenant status in the bootstrap slice.
	StatusActive = "active"

	// EventBootstrapped is the security-event type recording tenant creation.
	EventBootstrapped = "tenant.bootstrapped"

	// IDPrefix distinguishes tenant identifiers from other public IDs.
	IDPrefix = "tnt_"

	maxNameLength = 63
)

// Tenant is the strongest logical isolation boundary in a deployment.
type Tenant struct {
	ID     string `json:"tenant_id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// BootstrappedPayload is the versioned payload of an EventBootstrapped event.
type BootstrappedPayload struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
}

// NormalizeName lowercases and trims a tenant name so uniqueness checks are
// deterministic.
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidateName enforces the bounded slug shape accepted for normalized tenant
// names: lowercase letters, digits, and interior hyphens.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("tenant name is required")
	}
	if len(name) > maxNameLength {
		return fmt.Errorf("tenant name must not exceed %d bytes", maxNameLength)
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return errors.New("tenant name must not start or end with a hyphen")
	}
	for _, character := range name {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '-':
		default:
			return fmt.Errorf("tenant name contains unsupported character %q", character)
		}
	}
	return nil
}

// NewID returns a random public tenant identifier. Public IDs are random so
// they reveal no creation order and are never secrets.
func NewID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate tenant ID: %w", err)
	}
	return IDPrefix + hex.EncodeToString(value), nil
}

// ValidateID rejects values that cannot be SESAME tenant identifiers.
func ValidateID(id string) error {
	if !strings.HasPrefix(id, IDPrefix) || len(id) != len(IDPrefix)+32 {
		return errors.New("tenant ID must be tnt_ followed by 32 hex characters")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, IDPrefix)); err != nil {
		return errors.New("tenant ID must be tnt_ followed by 32 hex characters")
	}
	return nil
}
