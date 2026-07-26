package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Pushed authorization requests (RFC 9126) move the authorization request off
// the browser's address bar and onto a back channel the client authenticates
// on.
//
// What that buys is integrity. In a plain code flow every parameter — scopes,
// redirect URI, the PKCE challenge — travels through the user agent, where it
// lands in history, in referrers, in logs, and within reach of anything that
// can rewrite a URL. PAR replaces all of it with one opaque reference to a
// request the engine has already validated and stored, so what the user agent
// carries can no longer be edited into something else.
//
// Two rules make that real, and both are enforced here rather than trusted:
// the reference is single use, and a request presented by reference may not
// be combined with loose parameters. Merging would hand back exactly the
// tampering PAR exists to remove.

const (
	// EventPushedRequestCreated records a validated, stored authorization
	// request awaiting a browser.
	EventPushedRequestCreated = "oidc.pushed_request_created"
	// EventPushedRequestConsumed records the reference being spent. Single
	// use, so a replay fails across a restart.
	EventPushedRequestConsumed = "oidc.pushed_request_consumed"

	// PushedRequestIDPrefix distinguishes public pushed-request identifiers.
	PushedRequestIDPrefix = "par_"

	// RequestURIPrefix is the URN form RFC 9126 requires. It is a namespace,
	// not a location: nothing ever dereferences it.
	RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

	// PushedRequestLifetime bounds the gap between pushing a request and the
	// browser arriving with it. RFC 9126 recommends seconds rather than
	// minutes, and there is no reason for a longer window: the client has
	// just built the redirect it is about to issue.
	PushedRequestLifetime = 90 * time.Second

	pushedRequestBytes = 32
)

// PushedRequest is one validated authorization request held for a browser.
//
// The whole request is stored rather than a digest of it, because the point is
// to hand it back intact later — unlike a code or a secret, it is not a
// credential and there is nothing in it to keep from an attacker who already
// holds the store.
type PushedRequest struct {
	ID                  string   `json:"pushed_request_id"`
	TenantID            string   `json:"tenant_id"`
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	CreatedAt           string   `json:"created_at"`
	ExpiresAt           string   `json:"expires_at"`
	// Consumed marks a spent reference. The record is kept rather than
	// deleted so a replay is refused for a known reason instead of an
	// indistinguishable "not found".
	Consumed bool `json:"consumed,omitempty"`
}

// PushedRequestCreatedPayload is the versioned payload of
// EventPushedRequestCreated. Every field is a scalar or a flat array of
// scalars, per FYLO's document model.
type PushedRequestCreatedPayload struct {
	PushedRequestID     string   `json:"pushed_request_id"`
	TenantID            string   `json:"tenant_id"`
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	CreatedAt           string   `json:"created_at"`
	ExpiresAt           string   `json:"expires_at"`
}

// PushedRequestConsumedPayload is the versioned payload of
// EventPushedRequestConsumed.
type PushedRequestConsumedPayload struct {
	PushedRequestID string `json:"pushed_request_id"`
	TenantID        string `json:"tenant_id"`
	ConsumedAt      string `json:"consumed_at"`
}

// NewPushedRequestID returns a random pushed-request identifier.
func NewPushedRequestID() (string, error) {
	value := make([]byte, pushedRequestBytes/2)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate pushed request ID: %w", err)
	}
	return PushedRequestIDPrefix + hex.EncodeToString(value), nil
}

// ValidatePushedRequestID rejects values that cannot be one.
func ValidatePushedRequestID(id string) error {
	if !strings.HasPrefix(id, PushedRequestIDPrefix) ||
		len(id) != len(PushedRequestIDPrefix)+pushedRequestBytes {
		return fmt.Errorf("pushed request ID must be %s followed by %d hex characters",
			PushedRequestIDPrefix, pushedRequestBytes)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(id, PushedRequestIDPrefix)); err != nil {
		return fmt.Errorf("pushed request ID must be %s followed by %d hex characters",
			PushedRequestIDPrefix, pushedRequestBytes)
	}
	return nil
}

// RequestURI renders the reference a client puts in its redirect.
func RequestURI(pushedRequestID string) string {
	return RequestURIPrefix + pushedRequestID
}

// ParseRequestURI recovers the identifier from a reference.
//
// The prefix is required exactly. A reference that merely ends in something
// identifier-shaped is refused rather than salvaged: this value arrives from a
// user agent, and being liberal about its shape is how a lookup starts
// accepting things the client never pushed.
func ParseRequestURI(requestURI string) (string, error) {
	if !strings.HasPrefix(requestURI, RequestURIPrefix) {
		return "", fmt.Errorf("request_uri must begin with %s", RequestURIPrefix)
	}
	id := strings.TrimPrefix(requestURI, RequestURIPrefix)
	if err := ValidatePushedRequestID(id); err != nil {
		return "", err
	}
	return id, nil
}

// Usable reports whether a reference may still be redeemed.
func (p PushedRequest) Usable(now time.Time) bool {
	return !p.Consumed && p.Live(now)
}

// Live reports whether a reference is still inside its window, spent or not.
//
// This is what decides whether a record is worth keeping, and it is
// deliberately not Usable. Past the deadline a spent and an unspent reference
// are refused alike — on the deadline — so neither has anything left to say;
// inside the window a spent one is the only thing standing between an observed
// reference and a second redemption.
func (p PushedRequest) Live(now time.Time) bool {
	deadline, err := time.Parse(time.RFC3339Nano, p.ExpiresAt)
	if err != nil {
		// A reference whose deadline cannot be read is not one to honour.
		return false
	}
	return now.Before(deadline)
}
