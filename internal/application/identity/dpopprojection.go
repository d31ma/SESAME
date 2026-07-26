package identity

import (
	"fmt"
	"sort"
	"time"

	"github.com/d31ma/sesame/internal/domain/audit"
	oidcdomain "github.com/d31ma/sesame/internal/domain/oidc"
)

func (s *Service) applyDPoPProofSpent(event audit.Event) error {
	var payload oidcdomain.DPoPProofSpentPayload
	if err := decodeStrict(event.Payload, &payload); err != nil {
		return fmt.Errorf("decode %s payload at sequence %d: %w", event.Type, event.Sequence, err)
	}
	s.dpopProofs[dpopProofKey(payload.Thumbprint, payload.ProofID)] = dpopProofRecord{
		ID:         payload.ProofID,
		Thumbprint: payload.Thumbprint,
		TenantID:   payload.TenantID,
		ExpiresAt:  payload.ExpiresAt,
	}
	return nil
}

func (s *Service) admitDPoPProof(restored DPoPProofState) error {
	if restored.Proof.ID == "" || restored.Proof.Thumbprint == "" {
		return fmt.Errorf("a restored DPoP proof has no identifier")
	}
	s.dpopProofs[dpopProofKey(restored.Proof.Thumbprint, restored.Proof.ID)] = restored.Proof
	return nil
}

// pruneDPoPProofsLocked drops spent identifiers past any possible use.
//
// A proof is refused on its own `iat` once its window has closed, so an
// identifier only has to be remembered for that window — one minute. Without
// this the store would grow by one entry per request forever, which for the
// busiest surface in the engine is not a slow leak.
func (s *Service) pruneDPoPProofsLocked(now time.Time) {
	for key, proof := range s.dpopProofs {
		deadline, err := time.Parse(time.RFC3339Nano, proof.ExpiresAt)
		if err != nil || !now.Before(deadline) {
			delete(s.dpopProofs, key)
		}
	}
}

func (s *Service) exportDPoPProofsLocked() []DPoPProofState {
	now := s.now()
	proofs := make([]DPoPProofState, 0, len(s.dpopProofs))
	for _, proof := range s.dpopProofs {
		deadline, err := time.Parse(time.RFC3339Nano, proof.ExpiresAt)
		if err != nil || !now.Before(deadline) {
			continue
		}
		proofs = append(proofs, DPoPProofState{Proof: proof})
	}
	sort.Slice(proofs, func(left, right int) bool {
		return dpopProofKey(proofs[left].Proof.Thumbprint, proofs[left].Proof.ID) <
			dpopProofKey(proofs[right].Proof.Thumbprint, proofs[right].Proof.ID)
	})
	return proofs
}
