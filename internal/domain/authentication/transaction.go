// Package authentication defines the persisted state machine that proves a
// principal's identity.
//
// The engine owns every transition. An external client may render prompts
// and carry a handle, but it can never choose the next state: the only
// inputs are the events recorded here, and every transition is checked
// against the declared machine rather than trusted from the caller.
package authentication

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// EventStarted records a transaction beginning for one identifier.
	EventStarted = "authentication.started"
	// EventFactorVerified records one satisfied factor.
	EventFactorVerified = "authentication.factor_verified"
	// EventFailed records a terminal failure, including exhausted attempts.
	EventFailed = "authentication.failed"
	// EventCompleted records a transaction issuing its result.
	EventCompleted = "authentication.completed"

	// IDPrefix distinguishes public transaction identifiers.
	IDPrefix = "atx_"

	// MaxAttempts bounds credential guesses inside one transaction.
	MaxAttempts = 5
	// Lifetime bounds how long a started transaction may be completed.
	Lifetime = 10 * time.Minute

	// The implemented factor kinds.
	FactorPassword     = "password"
	FactorTOTP         = "totp"
	FactorRecoveryCode = "recovery_code"
	// FactorPasskey is the only phishing-resistant one: the authenticator
	// signs over the origin the browser is actually talking to.
	FactorPasskey = "passkey"

	// AssurancePassword is the assurance a password alone establishes;
	// AssuranceMFA is what a second factor on top of it establishes.
	AssurancePassword = "password"
	AssuranceMFA      = "mfa"
	// AssuranceFederated is what an external provider's assertion
	// establishes. It is deliberately distinct from AssurancePassword:
	// SESAME did not witness the credential, it trusted a third party's
	// statement about one. Whether that is enough for a given action is a
	// policy question, and collapsing it into "password" would answer that
	// question silently and permanently.
	AssuranceFederated = "federated"
)

// States of the authentication machine. Started and AwaitingFactor are the
// only states from which work continues; the rest are terminal.
const (
	StateStarted        = "started"
	StateAwaitingFactor = "awaiting_factor"
	StateCompleted      = "completed"
	StateFailed         = "failed"
)

// Stable failure reasons. They are safe to return to a caller: none of them
// distinguishes "no such principal" from "wrong password", because that
// distinction is an enumeration oracle.
const (
	ReasonInvalidCredentials = "invalid_credentials"
	ReasonAttemptsExhausted  = "attempts_exhausted"
	ReasonExpired            = "expired"
	ReasonAbandoned          = "abandoned"
)

// Transaction is one persisted authentication attempt.
type Transaction struct {
	ID       string `json:"transaction_id"`
	TenantID string `json:"tenant_id"`
	// PrincipalID is empty when the identifier matched nothing. The
	// transaction still runs so an attacker cannot distinguish a known
	// identifier from an unknown one by whether a transaction started.
	PrincipalID string `json:"principal_id,omitempty"`
	State       string `json:"state"`
	Attempts    int    `json:"attempts"`
	Assurance   string `json:"assurance,omitempty"`
	FailureCode string `json:"failure_code,omitempty"`
	StartedAt   string `json:"started_at"`
	ExpiresAt   string `json:"expires_at"`
	SessionID   string `json:"session_id,omitempty"`
	// PasskeyChallenge is the engine-issued value a passkey assertion must
	// sign over. It lives on the transaction so it is durable and single-use
	// per transaction: a challenge the caller chose, or one that outlived its
	// transaction, would let a captured assertion be replayed.
	PasskeyChallenge string `json:"passkey_challenge,omitempty"`
}

// StartedPayload is the versioned payload of an EventStarted event. It
// records the normalized identifier's namespace only; the value is not
// stored because a failed transaction would otherwise leave a durable record
// of an address someone typed.
type StartedPayload struct {
	TransactionID       string `json:"transaction_id"`
	TenantID            string `json:"tenant_id"`
	PrincipalID         string `json:"principal_id,omitempty"`
	IdentifierNamespace string `json:"identifier_namespace"`
	StartedAt           string `json:"started_at"`
	ExpiresAt           string `json:"expires_at"`
	// PasskeyChallenge is not a secret — it is a nonce the caller must have
	// an assertion over — so recording it durably is what makes replay after
	// a restart impossible rather than merely unlikely.
	PasskeyChallenge string `json:"passkey_challenge,omitempty"`
}

// FactorVerifiedPayload is the versioned payload of an EventFactorVerified
// event.
type FactorVerifiedPayload struct {
	TransactionID string `json:"transaction_id"`
	TenantID      string `json:"tenant_id"`
	PrincipalID   string `json:"principal_id"`
	Factor        string `json:"factor"`
	Assurance     string `json:"assurance"`
	Attempts      int    `json:"attempts"`
}

// FailedPayload is the versioned payload of an EventFailed event.
type FailedPayload struct {
	TransactionID string `json:"transaction_id"`
	TenantID      string `json:"tenant_id"`
	Reason        string `json:"reason"`
	Attempts      int    `json:"attempts"`
}

// CompletedPayload is the versioned payload of an EventCompleted event.
type CompletedPayload struct {
	TransactionID string `json:"transaction_id"`
	TenantID      string `json:"tenant_id"`
	PrincipalID   string `json:"principal_id"`
	SessionID     string `json:"session_id"`
}

// NewID returns a random public transaction identifier. It is a handle, not
// a secret: possessing it does not authenticate anyone.
func NewID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate transaction ID: %w", err)
	}
	return IDPrefix + hex.EncodeToString(value), nil
}

// ValidateID rejects values that cannot be transaction identifiers.
func ValidateID(id string) error {
	if !strings.HasPrefix(id, IDPrefix) || len(id) != len(IDPrefix)+32 {
		return errors.New("transaction ID must be atx_ followed by 32 hex characters")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, IDPrefix)); err != nil {
		return errors.New("transaction ID must be atx_ followed by 32 hex characters")
	}
	return nil
}

// Terminal reports whether a state accepts no further transitions.
func Terminal(state string) bool {
	return state == StateCompleted || state == StateFailed
}

// Expired reports whether a transaction may no longer be advanced at the
// given time. An unparseable expiry is treated as expired, so a transaction
// whose bound cannot be read is never unbounded.
func (t Transaction) Expired(now time.Time) bool {
	expiry, err := time.Parse(time.RFC3339Nano, t.ExpiresAt)
	if err != nil {
		return true
	}
	return !now.Before(expiry)
}

// CanAttempt reports whether a transaction may accept another factor
// attempt, and why not when it may not.
func (t Transaction) CanAttempt(now time.Time) (bool, string) {
	if Terminal(t.State) {
		return false, t.FailureCode
	}
	if t.Expired(now) {
		return false, ReasonExpired
	}
	if t.Attempts >= MaxAttempts {
		return false, ReasonAttemptsExhausted
	}
	return true, ""
}

// ValidateTransition reports whether the machine permits moving from one
// state to another. Unknown states and terminal-state departures are
// rejected, so a replayed ledger cannot smuggle in a transition this binary
// does not implement.
func ValidateTransition(from, to string) error {
	allowed := map[string][]string{
		StateStarted:        {StateAwaitingFactor, StateFailed},
		StateAwaitingFactor: {StateAwaitingFactor, StateCompleted, StateFailed},
	}
	targets, known := allowed[from]
	if !known {
		return fmt.Errorf("authentication state %q accepts no transitions", from)
	}
	for _, candidate := range targets {
		if candidate == to {
			return nil
		}
	}
	return fmt.Errorf("authentication transition %q -> %q is not permitted", from, to)
}
