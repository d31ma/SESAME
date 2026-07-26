// Consent.
//
// Registering a client declares which scopes it *may* ask for. That is an
// administrator's decision. It is not the user's, and until now nothing in
// SESAME recorded a user ever agreeing to anything — an authorization code was
// issued the moment authentication succeeded.
//
// That is defensible for a first-party client, where the administrator who
// registered it and the organization running the account are the same party.
// It is not defensible for a third-party client, where "this app may request
// your email" was decided by someone who is not the person whose email it is.
//
// Consent closes that gap: a third-party client needs a durable record that
// this principal agreed to these scopes for this client, and the record is
// checked against the scopes actually requested rather than the scopes
// registered.
package oidc

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	// EventConsentGranted records a principal agreeing to a scope set.
	EventConsentGranted = "oidc.consent_granted"
	// EventConsentWithdrawn records a durable, replay-safe withdrawal.
	EventConsentWithdrawn = "oidc.consent_withdrawn"

	// AudienceFirstParty and AudienceThirdParty decide whether a client
	// needs the user in the loop.
	AudienceFirstParty = "first_party"
	AudienceThirdParty = "third_party"
)

// Consent is one principal's standing agreement for one client.
//
// Scopes are the exact set agreed to. A later request for anything outside
// them needs a fresh decision: silently widening a standing consent is the
// same failure as widening a refresh token's scopes.
type Consent struct {
	PrincipalID string   `json:"principal_id"`
	ClientID    string   `json:"client_id"`
	TenantID    string   `json:"tenant_id"`
	Scopes      []string `json:"scopes"`
	GrantedAt   string   `json:"granted_at"`
	Withdrawn   bool     `json:"withdrawn,omitempty"`
}

// ConsentGrantedPayload is the versioned payload of EventConsentGranted.
type ConsentGrantedPayload struct {
	PrincipalID string   `json:"principal_id"`
	ClientID    string   `json:"client_id"`
	TenantID    string   `json:"tenant_id"`
	Scopes      []string `json:"scopes"`
	GrantedAt   string   `json:"granted_at"`
}

// ConsentWithdrawnPayload is the versioned payload of EventConsentWithdrawn.
type ConsentWithdrawnPayload struct {
	PrincipalID string `json:"principal_id"`
	ClientID    string `json:"client_id"`
	TenantID    string `json:"tenant_id"`
}

// ValidateAudience enforces the two modelled client audiences.
func ValidateAudience(audience string) error {
	if audience != AudienceFirstParty && audience != AudienceThirdParty {
		return fmt.Errorf("client audience must be %q or %q", AudienceFirstParty, AudienceThirdParty)
	}
	return nil
}

// RequiresConsent reports whether this client needs a recorded user decision.
//
// An unset audience is treated as third party. A client registered before
// consent existed, or by a caller that omitted the field, gets the stricter
// rule rather than the looser one — a default that fails open here would
// silently exempt exactly the clients most likely to need it.
func (c Client) RequiresConsent() bool {
	return c.Audience != AudienceFirstParty
}

// Covers reports whether a standing consent already authorizes every
// requested scope, naming the first that it does not.
//
// A withdrawn consent covers nothing, and neither does one whose scope set no
// longer contains what is being asked for.
func (c Consent) Covers(requested []string) (bool, string) {
	if c.Withdrawn {
		return false, ""
	}
	for _, scope := range requested {
		if !slices.Contains(c.Scopes, scope) {
			return false, scope
		}
	}
	return true, ""
}

// MergeScopes returns the union of an existing consent and a newly agreed
// set, so re-consenting to one more scope does not silently drop the others.
func MergeScopes(existing, granted []string) []string {
	merged := slices.Clone(existing)
	for _, scope := range granted {
		if !slices.Contains(merged, scope) {
			merged = append(merged, scope)
		}
	}
	slices.Sort(merged)
	return merged
}

// ValidateConsentScopes enforces a bounded, well-formed agreed scope set.
func ValidateConsentScopes(scopes []string) error {
	if len(scopes) == 0 {
		return errors.New("consent requires at least one scope")
	}
	if len(scopes) > maxScopes {
		return fmt.Errorf("consent must not exceed %d scopes", maxScopes)
	}
	for _, scope := range scopes {
		if err := ValidateScope(scope); err != nil {
			return err
		}
	}
	return nil
}

// FormatConsentTime renders a grant timestamp.
func FormatConsentTime(at time.Time) string { return at.Format(time.RFC3339Nano) }
