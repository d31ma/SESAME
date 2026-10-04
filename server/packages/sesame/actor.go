package sesame

import "context"

const (
	actorRequestField  = "actor"
	standardsOperation = "standards.dispatch"
)

// Actor names the signed-in principal a host acts for. The engine records
// it as principal:<tenant_id>/<principal_id>/<session_id> on every event the
// request writes, after checking that the session is live and belongs to that
// principal and tenant. It holds no secret and grants no access.
type Actor struct {
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	SessionID   string `json:"session_id"`
}

type actorContextKey struct{}

// WithActor returns a context whose requests are attributed to actor. The
// client sends it only to an engine whose system.version lists "actor" in
// request_fields, and never on standards.dispatch. Take actor only from a
// session the host has just verified, never from caller-supplied input. The
// engine refuses a mismatch with invalid_actor, actor_session_invalid, or
// actor_tenant_mismatch; none of them is retryable.
func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actor)
}

func actorFrom(ctx context.Context) *Actor {
	actor, found := ctx.Value(actorContextKey{}).(Actor)
	if !found {
		return nil
	}
	return &actor
}
