package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

// Stable pushed-request errors.
var (
	// ErrRequestURINotFound covers unknown, expired, spent, and cross-client
	// references alike. One answer: a browser-facing endpoint that told them
	// apart would report on requests other clients had pushed.
	ErrRequestURINotFound = errors.New("request_uri not found")
	// ErrRequestURIConflict reports an authorization request that carries
	// both a reference and loose parameters.
	ErrRequestURIConflict = errors.New(
		"a request_uri may not be combined with other authorization parameters")
)

// PushedAuthorizationRequest is what a client gets back for its redirect.
type PushedAuthorizationRequest struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

// PushedAuthorizationStart validates an authorization request on the back
// channel and stores it behind an opaque reference.
//
// The client authenticates here, which is the other half of what PAR buys: a
// confidential client's request is now attributable before a browser is ever
// involved, so a request that arrives at the authorization endpoint is one
// this client actually made.
func (s *Service) PushedAuthorizationStart(
	ctx context.Context,
	request AuthorizationRequest,
	clientSecret, actor string,
) (PushedAuthorizationRequest, error) {
	if err := s.requireLedgerAndActor(actor); err != nil {
		return PushedAuthorizationRequest{}, err
	}
	// ClientAuthenticate takes the lock itself.
	client, err := s.ClientAuthenticate(request.ClientID, clientSecret)
	if err != nil {
		return PushedAuthorizationRequest{}, err
	}
	validated, err := s.validateAuthorizationRequest(request, client)
	if err != nil {
		return PushedAuthorizationRequest{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.storePushedRequestLocked(ctx, client, validated, actor)
}

// validateAuthorizationRequest applies exactly the checks the authorization
// endpoint applies.
//
// Sharing them is the point: a request validated at push time and then
// re-validated differently at redemption would let a client push something the
// authorization endpoint would have refused.
func (s *Service) validateAuthorizationRequest(
	request AuthorizationRequest,
	client oidcdomain.Client,
) (AuthorizationRequest, error) {
	if err := oidcdomain.ValidateResponseType(request.ResponseType); err != nil {
		return AuthorizationRequest{}, err
	}
	if err := oidcdomain.ValidateCodeChallenge(
		request.CodeChallenge, request.CodeChallengeMethod); err != nil {
		return AuthorizationRequest{}, err
	}
	if err := oidcdomain.ValidateState(request.State); err != nil {
		return AuthorizationRequest{}, err
	}
	if err := oidcdomain.ValidateNonce(request.Nonce); err != nil {
		return AuthorizationRequest{}, err
	}
	if !oidcdomain.MatchRedirectURI(client.RedirectURIs, request.RedirectURI) {
		return AuthorizationRequest{}, ErrInvalidRedirectURI
	}
	scopes, err := oidcdomain.NormalizeScopes(request.Scopes)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	if allowed, offending := client.AllowsScopes(scopes); !allowed {
		return AuthorizationRequest{}, fmt.Errorf("%w: %s", ErrScopeNotAllowed, offending)
	}
	request.Scopes = scopes
	return request, nil
}

func (s *Service) storePushedRequestLocked(
	ctx context.Context,
	client oidcdomain.Client,
	request AuthorizationRequest,
	actor string,
) (PushedAuthorizationRequest, error) {
	id, err := oidcdomain.NewPushedRequestID()
	if err != nil {
		return PushedAuthorizationRequest{}, err
	}
	now := s.now()
	// Pruning here rather than on a timer: this is the only moment the map
	// grows, so it is the only moment it can need shrinking, and an engine
	// nobody is pushing to has nothing to clean up.
	s.prunePushedRequestsLocked(now)
	expiresAt := now.Add(oidcdomain.PushedRequestLifetime)

	event, err := s.ledger.Append(ctx, oidcdomain.EventPushedRequestCreated,
		client.TenantID, actor,
		oidcdomain.PushedRequestCreatedPayload{
			PushedRequestID:     id,
			TenantID:            client.TenantID,
			ClientID:            client.ID,
			RedirectURI:         request.RedirectURI,
			ResponseType:        request.ResponseType,
			Scopes:              request.Scopes,
			State:               request.State,
			Nonce:               request.Nonce,
			CodeChallenge:       request.CodeChallenge,
			CodeChallengeMethod: request.CodeChallengeMethod,
			CreatedAt:           now.Format(time.RFC3339Nano),
			ExpiresAt:           expiresAt.Format(time.RFC3339Nano),
		})
	if err != nil {
		return PushedAuthorizationRequest{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyPushedRequestCreated(event); err != nil {
		return PushedAuthorizationRequest{}, err
	}
	s.writeSnapshotLocked(ctx, id)

	return PushedAuthorizationRequest{
		RequestURI: oidcdomain.RequestURI(id),
		ExpiresIn:  int64(oidcdomain.PushedRequestLifetime / time.Second),
	}, nil
}

// resolvePushedRequestLocked spends a reference and returns the request it
// stood for.
//
// Spending happens here, before the interaction is created, so a reference is
// consumed exactly once even if what follows fails. A reference that survived
// a failed authorization could be replayed by anything that saw the redirect.
func (s *Service) resolvePushedRequestLocked(
	ctx context.Context,
	requestURI, clientID, actor string,
) (AuthorizationRequest, error) {
	id, err := oidcdomain.ParseRequestURI(requestURI)
	if err != nil {
		return AuthorizationRequest{}, ErrRequestURINotFound
	}
	pushed, exists := s.pushedRequests[id]
	now := s.now()
	// The reference is bound to the client that pushed it: a second client
	// quoting somebody else's request_uri gets the same answer as one quoting
	// a reference that never existed.
	if !exists || !pushed.Usable(now) || pushed.ClientID != clientID {
		return AuthorizationRequest{}, ErrRequestURINotFound
	}

	event, err := s.ledger.Append(ctx, oidcdomain.EventPushedRequestConsumed,
		pushed.TenantID, actor,
		oidcdomain.PushedRequestConsumedPayload{
			PushedRequestID: id,
			TenantID:        pushed.TenantID,
			ConsumedAt:      now.Format(time.RFC3339Nano),
		})
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}
	if err := s.applyPushedRequestConsumed(event); err != nil {
		return AuthorizationRequest{}, err
	}

	return AuthorizationRequest{
		ClientID:            pushed.ClientID,
		RedirectURI:         pushed.RedirectURI,
		ResponseType:        pushed.ResponseType,
		Scopes:              pushed.Scopes,
		State:               pushed.State,
		Nonce:               pushed.Nonce,
		CodeChallenge:       pushed.CodeChallenge,
		CodeChallengeMethod: pushed.CodeChallengeMethod,
	}, nil
}

// carriesLooseParameters reports whether a request quoting a reference also
// carries parameters of its own.
//
// RFC 9126 says the authorization server must not merge them, and the reason
// is the whole point of PAR: the reference stands for a request that was
// validated and fixed on a back channel, and honouring a redirect URI or a
// scope set that arrived beside it in the browser would restore exactly the
// tampering the push removed. SESAME refuses rather than ignores, so a client
// that sends both learns it immediately instead of shipping a flow whose
// parameters are silently dropped.
func carriesLooseParameters(request AuthorizationRequest) bool {
	return request.RedirectURI != "" ||
		request.ResponseType != "" ||
		len(request.Scopes) != 0 ||
		request.State != "" ||
		request.Nonce != "" ||
		request.CodeChallenge != "" ||
		request.CodeChallengeMethod != ""
}
