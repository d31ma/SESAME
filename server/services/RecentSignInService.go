import (
	"time"

	"github.com/d31ma/sesame/server/packages/host"
)

// @Service
type RecentSignInService struct {
	// @Needs
	engineService *EngineService
	clockShift    time.Duration
}

func (service *RecentSignInService) Require(caller Caller, failure error) error {
	session, failure := service.session(caller, failure)
	issuedAt, failure := service.issuedAt(session, failure)
	return service.withinWindow(issuedAt, failure)
}

func (service *RecentSignInService) session(caller Caller, failure error) (Session, error) {
	if failure != nil {
		return Session{}, failure
	}
	session := Session{}
	credential := SessionCredential{SessionID: caller.SessionID, SessionSecret: caller.SessionSecret}
	failure = service.engineService.Call("session.verify", credential, &session)
	return session, failure
}

func (service *RecentSignInService) issuedAt(session Session, failure error) (time.Time, error) {
	if failure != nil {
		return time.Time{}, failure
	}
	return time.Parse(time.RFC3339Nano, session.IssuedAt)
}

func (service *RecentSignInService) withinWindow(issuedAt time.Time, failure error) error {
	if failure != nil || service.now().Sub(issuedAt) <= service.window() {
		return failure
	}
	return &host.ReauthenticationRequiredError{}
}

func (service *RecentSignInService) now() time.Time {
	return time.Now().Add(service.clockShift)
}

func (service *RecentSignInService) window() time.Duration {
	return 10 * time.Minute
}
