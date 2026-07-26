package identity

import (
	"fmt"
	"sort"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

// PushedRequestState is one pushed authorization request in a snapshot.
type PushedRequestState struct {
	Request oidcdomain.PushedRequest `json:"request"`
}

func (s *Service) applyPushedRequestCreated(event audit.Event) error {
	var payload oidcdomain.PushedRequestCreatedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.pushedRequests[payload.PushedRequestID] = oidcdomain.PushedRequest{
		ID:                  payload.PushedRequestID,
		TenantID:            payload.TenantID,
		ClientID:            payload.ClientID,
		RedirectURI:         payload.RedirectURI,
		ResponseType:        payload.ResponseType,
		Scopes:              payload.Scopes,
		State:               payload.State,
		Nonce:               payload.Nonce,
		CodeChallenge:       payload.CodeChallenge,
		CodeChallengeMethod: payload.CodeChallengeMethod,
		CreatedAt:           payload.CreatedAt,
		ExpiresAt:           payload.ExpiresAt,
	}
	return nil
}

func (s *Service) applyPushedRequestConsumed(event audit.Event) error {
	var payload oidcdomain.PushedRequestConsumedPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	request, exists := s.pushedRequests[payload.PushedRequestID]
	if !exists {
		return nil
	}
	// Marked rather than deleted, so a replayed reference is refused for a
	// known reason instead of an indistinguishable "not found" — and, more
	// importantly, so the single-use claim survives a restart.
	request.Consumed = true
	s.pushedRequests[payload.PushedRequestID] = request
	return nil
}

func (s *Service) admitPushedRequest(restored PushedRequestState) error {
	if err := oidcdomain.ValidatePushedRequestID(restored.Request.ID); err != nil {
		return err
	}
	s.pushedRequests[restored.Request.ID] = restored.Request
	return nil
}

// prunePushedRequestsLocked drops records past any possible use.
//
// The rule is the deadline, not consumption: a spent reference inside its
// window is exactly the record that refuses a replay, so dropping it early
// would hand back the single-use guarantee. Past the deadline neither kind
// decides anything, and keeping them would grow the map and every snapshot
// taken from it for the life of the process.
func (s *Service) prunePushedRequestsLocked(now time.Time) {
	for id, request := range s.pushedRequests {
		if !request.Live(now) {
			delete(s.pushedRequests, id)
		}
	}
}

func (s *Service) exportPushedRequestsLocked() []PushedRequestState {
	now := s.now()
	requests := make([]PushedRequestState, 0, len(s.pushedRequests))
	for _, request := range s.pushedRequests {
		if !request.Live(now) {
			continue
		}
		requests = append(requests, PushedRequestState{Request: request})
	}
	sort.Slice(requests, func(left, right int) bool {
		return requests[left].Request.ID < requests[right].Request.ID
	})
	return requests
}
