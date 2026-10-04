package audit

import (
	"errors"
	"strings"
)

const (
	principalActorPrefix    = "principal:"
	principalActorSeparator = "/"
	principalActorParts     = 3
)

// ErrMalformedPrincipalActor reports recorded actor text that starts like a
// principal actor but does not hold exactly a tenant, principal, and session.
var ErrMalformedPrincipalActor = errors.New("principal actor must be principal:<tenant_id>/<principal_id>/<session_id>")

// PrincipalActor is a calling principal that a trusted host attributes a
// request to. It changes who an event records, never what is allowed.
type PrincipalActor struct {
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	SessionID   string `json:"session_id"`
}

// String is the actor text an event records.
func (a PrincipalActor) String() string {
	parts := []string{a.TenantID, a.PrincipalID, a.SessionID}
	return principalActorPrefix + strings.Join(parts, principalActorSeparator)
}

// IsPrincipalActor reports whether recorded actor text names a principal
// rather than an operator.
func IsPrincipalActor(text string) bool {
	return strings.HasPrefix(text, principalActorPrefix)
}

// ParsePrincipalActor reads recorded actor text written by String.
func ParsePrincipalActor(text string) (PrincipalActor, error) {
	parts := strings.Split(strings.TrimPrefix(text, principalActorPrefix), principalActorSeparator)
	if !IsPrincipalActor(text) || len(parts) != principalActorParts {
		return PrincipalActor{}, ErrMalformedPrincipalActor
	}
	return PrincipalActor{TenantID: parts[0], PrincipalID: parts[1], SessionID: parts[2]}, nil
}
