import (
	"slices"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Service
// @NeedsAll
type PublicCallService struct {
	engineHelper *EngineHelper
}

func (service *PublicCallService) Call(call EngineCall) error {
	failure := service.requirePublic(call)
	return service.send(call, failure)
}

func (service *PublicCallService) requirePublic(call EngineCall) error {
	if slices.Contains(service.publicOperations(), call.Operation) {
		return nil
	}
	return &host.OperationNotPublicError{}
}

func (service *PublicCallService) send(call EngineCall, failure error) error {
	if failure != nil {
		return failure
	}
	return service.engineHelper.Call(call.Operation, call.Parameters, call.Result)
}

func (service *PublicCallService) publicOperations() []string {
	return []string{
		"authn.begin",
		"authn.complete",
		"authn.passkey_options",
		"authn.verify_passkey",
		"authn.verify_password",
		"authn.verify_recovery_code",
		"authn.verify_totp",
		"federation.login_complete",
		"oidc.device_authorize",
		"oidc.dpop_verify",
		"oidc.pushed_authorize",
		"saml.login_complete",
		"session.verify",
		"system.ping",
		"system.readiness",
		"system.version",
		"token.jwks",
	}
}
