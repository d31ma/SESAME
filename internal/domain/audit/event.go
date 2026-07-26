// Package audit defines SESAME's hash-chained security-event model. Events
// are the authoritative record of accepted security transitions; every other
// state is a rebuildable projection.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// EventKind marks documents that belong to the security ledger.
	EventKind = "security-event"
	// SchemaVersion is the current stored event schema.
	SchemaVersion = 1
)

// Event is one durable, hash-chained security event.
type Event struct {
	Kind          string          `json:"kind"`
	SchemaVersion int             `json:"schema_version"`
	Sequence      int64           `json:"sequence"`
	Type          string          `json:"type"`
	TenantID      string          `json:"tenant_id"`
	Actor         string          `json:"actor"`
	OccurredAt    string          `json:"occurred_at"`
	Payload       json.RawMessage `json:"payload"`
	PreviousHash  string          `json:"previous_hash"`
	Hash          string          `json:"hash"`
}

// Digest computes the event hash over every field except Hash itself.
func (e Event) Digest() string {
	hashed := e
	hashed.Hash = ""
	encoded, err := json.Marshal(hashed)
	if err != nil {
		// Event fields are plain data; marshalling cannot fail for values that
		// were themselves produced by JSON decoding.
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// VerifyChain fails closed on any sequence gap, hash mismatch, or broken
// previous-hash link in an ordered event slice.
func VerifyChain(events []Event) error {
	return VerifyChainFrom(events, 0, "")
}

// VerifyChainFrom verifies an ordered event slice that continues a chain
// whose last verified event had lastSequence and lastHash. A zero
// lastSequence with an empty lastHash verifies a complete chain.
func VerifyChainFrom(events []Event, lastSequence int64, lastHash string) error {
	previousHash := lastHash
	for index, event := range events {
		if event.Kind != EventKind {
			return fmt.Errorf("event at position %d has kind %q", index, event.Kind)
		}
		if event.Sequence != lastSequence+int64(index)+1 {
			return fmt.Errorf(
				"event sequence %d found at chain position %d",
				event.Sequence,
				lastSequence+int64(index)+1,
			)
		}
		if event.PreviousHash != previousHash {
			return fmt.Errorf("event %d does not link to its predecessor", event.Sequence)
		}
		if event.Hash == "" || event.Hash != event.Digest() {
			return fmt.Errorf("event %d fails hash verification", event.Sequence)
		}
		previousHash = event.Hash
	}
	return nil
}

// KnownEventTypes is the registry of security-event types this binary can
// replay. Replaying a ledger that contains an unregistered type fails closed:
// an unknown event could encode a security decision this binary would
// otherwise silently ignore.
var KnownEventTypes = map[string]struct{}{
	"tenant.bootstrapped":  {},
	"principal.created":    {},
	"principal.suspended":  {},
	"role.created":         {},
	"grant.created":        {},
	"grant.revoked":        {},
	"group.created":        {},
	"group.member_added":   {},
	"group.member_removed": {},

	"authenticator.password_set":          {},
	"authenticator.totp_enrolled":         {},
	"authenticator.totp_activated":        {},
	"authenticator.totp_used":             {},
	"authenticator.recovery_codes_issued": {},
	"authenticator.recovery_code_used":    {},
	"authenticator.passkey_registered":    {},
	"authenticator.passkey_used":          {},
	"authenticator.passkey_removed":       {},
	"authentication.started":              {},
	"authentication.factor_verified":      {},
	"authentication.failed":               {},
	"authentication.completed":            {},
	"session.issued":                      {},
	"session.revoked":                     {},

	"oidc_client.registered":     {},
	"oidc_client.secret_rotated": {},
	"oidc_client.disabled":       {},

	"oidc.interaction_started": {},
	"oidc.interaction_failed":  {},
	"oidc.code_issued":         {},
	"oidc.code_redeemed":       {},

	"oidc.refresh_issued":         {},
	"oidc.refresh_spent":          {},
	"oidc.refresh_family_revoked": {},

	"oidc.consent_granted":   {},
	"oidc.consent_withdrawn": {},

	// Inbound OIDC federation.
	"federation.provider_registered": {},
	"federation.provider_updated":    {},
	"federation.provider_disabled":   {},
	"federation.login_started":       {},
	"federation.login_completed":     {},
	"federation.login_failed":        {},
	"federation.subject_linked":      {},
	"federation.subject_unlinked":    {},

	// SCIM 2.0 provisioning.
	"scim_client.registered":    {},
	"scim_client.token_rotated": {},
	"scim_client.disabled":      {},
	"scim.user_provisioned":     {},
	"scim.user_updated":         {},
	"scim.user_deprovisioned":   {},

	// SAML 2.0.
	"oidc.pushed_request_created":  {},
	"oidc.pushed_request_consumed": {},
	"oidc.dpop_proof_spent":        {},

	"oidc.device_authorization_started":  {},
	"oidc.device_authorization_approved": {},
	"oidc.device_authorization_denied":   {},
	"oidc.device_code_redeemed":          {},

	"saml.provider_registered": {},
	"saml.provider_disabled":   {},
	"saml.login_started":       {},
	"saml.login_completed":     {},
	"saml.login_failed":        {},
}

// Upcast migrates one stored event to the current schema version. Version 1
// is current, so the upcast is the identity; the fail-closed unknown-version
// and unknown-type paths are the load-bearing part.
func Upcast(event Event) (Event, error) {
	if _, known := KnownEventTypes[event.Type]; !known {
		return Event{}, fmt.Errorf(
			"event sequence %d has unregistered type %q; refusing to replay a ledger this binary cannot interpret",
			event.Sequence,
			event.Type,
		)
	}
	switch event.SchemaVersion {
	case SchemaVersion:
		return event, nil
	default:
		return Event{}, fmt.Errorf(
			"event sequence %d has schema version %d; this binary supports %d",
			event.Sequence,
			event.SchemaVersion,
			SchemaVersion,
		)
	}
}

// Validate rejects events that cannot enter the ledger.
func (e Event) Validate() error {
	if e.Kind != EventKind {
		return fmt.Errorf("event kind must be %q", EventKind)
	}
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("event schema version must be %d", SchemaVersion)
	}
	if e.Sequence < 1 {
		return errors.New("event sequence must be positive")
	}
	if e.Type == "" {
		return errors.New("event type is required")
	}
	if e.Actor == "" {
		return errors.New("event actor is required")
	}
	if e.OccurredAt == "" {
		return errors.New("event occurred_at is required")
	}
	return nil
}
