import (
	"net/http"
	"slices"
	"strings"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Service
// @NeedsAll
type CallerService struct {
	engineHelper *EngineHelper
}

func (service *CallerService) Resolve(request *http.Request) (Caller, error) {
	credential, failure := service.credential(request.Header.Get(service.headerName()))
	session, failure := service.verify(credential, failure)
	caller, failure := service.caller(credential, session, service.rejection(failure))
	return caller, service.actAs(caller, failure)
}

func (service *CallerService) RequireTenant(caller Caller, tenantID string) error {
	checks := []bool{caller.TenantID != "", caller.TenantID == tenantID}
	return service.mismatch(checks)
}

func (service *CallerService) credential(value string) (SessionCredential, error) {
	sessionID, secret, found := strings.Cut(value, service.separator())
	checks := []bool{found, sessionID != "", secret != ""}
	if slices.Contains(checks, false) {
		return SessionCredential{}, &host.SessionRejectedError{}
	}
	return SessionCredential{SessionID: sessionID, SessionSecret: secret}, nil
}

func (service *CallerService) verify(credential SessionCredential, failure error) (Session, error) {
	if failure != nil {
		return Session{}, failure
	}
	session := Session{}
	failure = service.engineHelper.Call("session.verify", credential, &session)
	return session, failure
}

func (service *CallerService) caller(credential SessionCredential, session Session, failure error) (Caller, error) {
	if failure != nil {
		return Caller{}, failure
	}
	return Caller{
		TenantID:      session.TenantID,
		PrincipalID:   session.PrincipalID,
		SessionID:     session.SessionID,
		SessionSecret: credential.SessionSecret,
		IssuedAt:      session.IssuedAt,
	}, nil
}

func (service *CallerService) actAs(caller Caller, failure error) error {
	if failure == nil {
		service.engineHelper.ActAs(caller)
	}
	return failure
}

func (service *CallerService) rejection(failure error) error {
	if slices.Contains(service.rejectedCodes(), ProtocolErrorUtils{}.Code(failure)) {
		return &host.SessionRejectedError{}
	}
	return failure
}

func (service *CallerService) mismatch(checks []bool) error {
	if slices.Contains(checks, false) {
		return &host.TenantMismatchError{}
	}
	return nil
}

func (service *CallerService) rejectedCodes() []string {
	return []string{"session_not_found", "session_inactive", "invalid_request"}
}

func (service *CallerService) headerName() string {
	return "Sesame-Session"
}

func (service *CallerService) separator() string {
	return ":"
}
