package identity

import (
	"errors"

	"github.com/d31ma/sesame/internal/domain/audit"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
)

// ErrActorSessionInvalid reports an attributed actor whose session is
// unknown, no longer usable, or held by another principal or tenant.
var ErrActorSessionInvalid = errors.New("actor does not hold a usable session in its tenant")

// VerifyActor checks that an attributed actor names a live session of that
// principal in that tenant. It looks the session up by ID only: the host that
// owns the pipe already proved the session secret with session.verify.
func (s *Service) VerifyActor(actor audit.PrincipalActor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := s.sessions[actor.SessionID]
	_, unusable := s.usableSessionLocked(stored, s.now())
	return actorVerdict(unusable, ownsSession(stored, actor))
}

func ownsSession(stored sessiondomain.Session, actor audit.PrincipalActor) bool {
	return stored.PrincipalID == actor.PrincipalID && stored.TenantID == actor.TenantID
}

func actorVerdict(unusable error, owned bool) error {
	if unusable != nil || !owned {
		return ErrActorSessionInvalid
	}
	return nil
}
