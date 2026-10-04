import (
	"slices"
	"time"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Service
type RecentSignInService struct {
	clockShift time.Duration
}

func (service *RecentSignInService) Require(caller Caller, failure error) error {
	issuedAt, failure := service.issuedAt(caller, failure)
	return service.withinWindow(issuedAt, failure)
}

func (service *RecentSignInService) Privileged(call EngineCall) bool {
	listed := slices.Contains(service.privilegedOperations(), call.Operation)
	return slices.Contains([]bool{call.Privileged, listed}, true)
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

func (service *RecentSignInService) privilegedOperations() []string {
	return []string{
		"authenticator.set_password",
		"authenticator.totp_enroll",
		"authenticator.totp_activate",
		"authenticator.recovery_codes_issue",
		"authenticator.passkey_register_begin",
		"authenticator.passkey_register_finish",
		"authenticator.passkey_remove",
		"federation.provider_register",
		"federation.provider_configure",
		"grant.create",
		"group.member_add",
		"oidc_client.register",
		"oidc_client.rotate_secret",
		"principal.suspend",
		"saml.provider_register",
		"scim.client_register",
		"scim.client_rotate_token",
	}
}
