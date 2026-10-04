package machine

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/d31ma/sesame/internal/domain/audit"
	principaldomain "github.com/d31ma/sesame/internal/domain/principal"
	sessiondomain "github.com/d31ma/sesame/internal/domain/session"
	tenantdomain "github.com/d31ma/sesame/internal/domain/tenant"
)

const (
	// ErrorInvalidActor reports an actor field that is not exactly a tenant,
	// principal, and session identifier, or one sent where attribution is
	// not accepted.
	ErrorInvalidActor = "invalid_actor"
	// ErrorActorSessionInvalid reports an actor whose session is unknown,
	// expired, revoked, suspended, or held by another principal or tenant.
	ErrorActorSessionInvalid = "actor_session_invalid"
	// ErrorActorTenantMismatch reports an attributed write that would record
	// an event in a tenant other than the actor's own.
	ErrorActorTenantMismatch = "actor_tenant_mismatch"

	// MaxActorBytes bounds the serialized actor field.
	MaxActorBytes = 512

	actorRequestField    = "actor"
	machineOperatorActor = "operator:machine"
	standardsOperation   = "standards.dispatch"
)

func requestFields() []string {
	return []string{actorRequestField}
}

func (p *Processor) attributeRequest(request Request) (Request, *Response) {
	if len(request.Actor) == 0 {
		request.recordedActor = machineOperatorActor
		return request, nil
	}
	actor, refusal := p.acceptActor(request)
	request.recordedActor = actor.String()
	return request, refusal
}

func (p *Processor) acceptActor(request Request) (audit.PrincipalActor, *Response) {
	actor, err := decodeActor(request.Actor)
	if err != nil {
		return actor, refuseActor(request.RequestID, ErrorInvalidActor, err.Error())
	}
	if request.Operation == standardsOperation {
		return actor, refuseActor(request.RequestID, ErrorInvalidActor,
			"standards.dispatch authenticates its caller by protocol and does not accept an actor")
	}
	if p.tenant == nil {
		return actor, refuseActor(request.RequestID, ErrorStorageNotConfigured,
			"actor attribution requires a configured FYLO root")
	}
	if err := p.tenant.VerifyActor(actor); err != nil {
		return actor, refuseActor(request.RequestID, ErrorActorSessionInvalid,
			"actor does not hold a usable session in its tenant")
	}
	return actor, nil
}

func refuseActor(requestID, code, message string) *Response {
	response := errorResponse(requestID, code, message)
	return &response
}

func decodeActor(raw json.RawMessage) (audit.PrincipalActor, error) {
	var actor audit.PrincipalActor
	if len(raw) > MaxActorBytes {
		return actor, errors.New("actor exceeds its maximum size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&actor); err != nil {
		return actor, errors.New("actor must be an object holding only tenant_id, principal_id, and session_id")
	}
	return actor, validateActorIdentifiers(actor)
}

func validateActorIdentifiers(actor audit.PrincipalActor) error {
	invalid := errors.Join(
		tenantdomain.ValidateID(actor.TenantID),
		principaldomain.ValidateID(actor.PrincipalID),
		sessiondomain.ValidateID(actor.SessionID),
	)
	if invalid != nil {
		return errors.New("actor tenant_id, principal_id, and session_id must be SESAME identifiers")
	}
	return nil
}
