import (
	"time"

	"github.com/d31ma/sesame/server/packages/host"
)

// @Service
type RecentSignInService struct {
	clockShift time.Duration
}

func (service *RecentSignInService) Require(caller Caller, failure error) error {
	issuedAt, failure := service.issuedAt(caller, failure)
	return service.withinWindow(issuedAt, failure)
}

func (service *RecentSignInService) issuedAt(caller Caller, failure error) (time.Time, error) {
	if failure != nil {
		return time.Time{}, failure
	}
	return time.Parse(time.RFC3339Nano, caller.IssuedAt)
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
