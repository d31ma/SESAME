package identity

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
	tokendomain "github.com/d31ma/sesame/internal/domain/token"
)

// Stable logout errors.
var (
	// ErrInvalidLogoutHint reports an id_token_hint SESAME cannot attribute
	// to a session it issued.
	ErrInvalidLogoutHint = errors.New("id_token_hint is not a token this deployment issued")
	// ErrInvalidPostLogoutRedirect reports a return URI the client has not
	// registered.
	ErrInvalidPostLogoutRedirect = errors.New("post-logout redirect URI is not registered for this client")
)

// LogoutRequest is an RP-initiated logout.
//
// The id_token_hint is required. SESAME is headless and holds no browser
// session of its own, so without a hint there is nothing that identifies which
// session to end — and guessing from anything the caller supplied directly
// would let one party log another out at will.
type LogoutRequest struct {
	IDTokenHint           string `json:"id_token_hint"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri,omitempty"`
	State                 string `json:"state,omitempty"`
}

// LogoutResult reports what the host should do next.
type LogoutResult struct {
	// RedirectURI is empty when the client asked for no return, in which case
	// the host renders its own confirmation.
	RedirectURI string `json:"redirect_uri,omitempty"`
	State       string `json:"state,omitempty"`
	ClientID    string `json:"client_id"`
	PrincipalID string `json:"principal_id"`
	SessionID   string `json:"session_id"`
	// SessionRevoked is false when the session had already ended. Logout is
	// idempotent; a user clicking twice is not an error.
	SessionRevoked bool `json:"session_revoked"`
}

// Logout ends the session an ID token was issued against.
//
// Revoking the session is the whole mechanism: every refresh grant checks that
// its session is unrevoked, so one durable revocation ends the browser session
// and every refresh token resting on it together, rather than leaving the
// client quietly able to mint more.
func (s *Service) Logout(ctx context.Context, request LogoutRequest, actor string) (LogoutResult, error) {
	if err := s.requireLedger(); err != nil {
		return LogoutResult{}, err
	}
	if request.IDTokenHint == "" {
		return LogoutResult{}, fmt.Errorf("%w: no hint was supplied", ErrInvalidLogoutHint)
	}
	if err := oidcdomain.ValidateState(request.State); err != nil {
		return LogoutResult{}, err
	}
	if actor == "" {
		return LogoutResult{}, errors.New("actor is required")
	}

	s.mu.Lock()
	if s.signingKey == nil {
		s.mu.Unlock()
		return LogoutResult{}, tokendomain.ErrNoSigningKey
	}
	if s.issuer == "" {
		s.mu.Unlock()
		return LogoutResult{}, ErrNoIssuer
	}
	signingKey, issuer, now := s.signingKey, s.issuer, s.now()
	s.mu.Unlock()

	// The audience is read from the hint rather than supplied, so a caller
	// cannot present one client's token while claiming to be another. An
	// expired hint is accepted: it authorizes nothing, and a user reaching
	// for "sign out" often does so because their tokens have aged.
	claims, body, err := signingKey.VerifyExpired(request.IDTokenHint, issuer, "", now)
	if err != nil {
		return LogoutResult{}, fmt.Errorf("%w: %v", ErrInvalidLogoutHint, err)
	}
	sessionID, _ := body["sid"].(string)
	if sessionID == "" || claims.Audience == "" || claims.Subject == "" {
		return LogoutResult{}, fmt.Errorf("%w: the hint names no session", ErrInvalidLogoutHint)
	}

	s.mu.Lock()
	stored, exists := s.clients[claims.Audience]
	if !exists {
		s.mu.Unlock()
		return LogoutResult{}, ErrClientNotFound
	}
	session, sessionExists := s.sessions[sessionID]
	// A hint naming a session belonging to somebody else, or to another
	// tenant, ends nothing.
	if sessionExists &&
		(session.PrincipalID != claims.Subject || session.TenantID != stored.Client.TenantID) {
		s.mu.Unlock()
		return LogoutResult{}, fmt.Errorf("%w: the hint does not match its session", ErrInvalidLogoutHint)
	}

	redirect := ""
	if request.PostLogoutRedirectURI != "" {
		if !oidcdomain.MatchRedirectURI(stored.Client.PostLogoutRedirectURIs, request.PostLogoutRedirectURI) {
			s.mu.Unlock()
			return LogoutResult{}, ErrInvalidPostLogoutRedirect
		}
		redirect = request.PostLogoutRedirectURI
	}
	alreadyEnded := !sessionExists || session.Status != "active"
	s.mu.Unlock()

	result := LogoutResult{
		RedirectURI: redirect,
		State:       request.State,
		ClientID:    claims.Audience,
		PrincipalID: claims.Subject,
		SessionID:   sessionID,
	}
	if alreadyEnded {
		// Idempotent: a second click is not an error, and reporting one
		// would tell the caller whether a session existed.
		return result, nil
	}
	if err := s.SessionRevoke(ctx, sessionID, "logout", actor); err != nil {
		return LogoutResult{}, err
	}
	result.SessionRevoked = true
	return result, nil
}

// LogoutRedirect builds the URL a host sends the browser to after a logout,
// echoing state exactly as supplied. It returns an empty string when the
// client asked for no return.
func LogoutRedirect(result LogoutResult) (string, error) {
	if result.RedirectURI == "" {
		return "", nil
	}
	target, err := url.Parse(result.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("post-logout redirect URI %q is not a valid URL", result.RedirectURI)
	}
	if result.State != "" {
		parameters := target.Query()
		parameters.Set("state", result.State)
		target.RawQuery = parameters.Encode()
	}
	return target.String(), nil
}
