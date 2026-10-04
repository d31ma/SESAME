import "net/http"

// @RequestRoute("/api/v1/authenticator")
// @NeedsAll
type AuthenticatorController struct {
	authenticatorService   *AuthenticatorService
	passkeyService         *PasskeyService
	principalTenantService *PrincipalTenantService
}

// @PostRoute("/set-password")
// @SignedIn
func (controller *AuthenticatorController) PostSetPassword(
	request *http.Request,
	// @FromBody
	body AuthenticatorPassword,
) (AuthenticatorPasswordSet, error) {
	var result AuthenticatorPasswordSet
	err := controller.authenticatorService.SetPassword(request, body, EngineCall{Operation: controller.setPasswordOperation(), Result: &result})
	return result, err
}

// @PostRoute("/totp-enroll")
// @SignedIn
func (controller *AuthenticatorController) PostTotpEnroll(
	request *http.Request,
	// @FromBody
	body AuthenticatorTotpIssuer,
) (AuthenticatorTotpEnrollment, error) {
	var result AuthenticatorTotpEnrollment
	err := controller.authenticatorService.TotpEnroll(request, body, EngineCall{Operation: "authenticator.totp_enroll", Result: &result})
	return result, err
}

// @PostRoute("/totp-activate")
// @SignedIn
func (controller *AuthenticatorController) PostTotpActivate(
	request *http.Request,
	// @FromBody
	body AuthenticatorTotpCode,
) (AuthenticatorTotpActivation, error) {
	var result AuthenticatorTotpActivation
	err := controller.authenticatorService.TotpActivate(request, body, EngineCall{Operation: "authenticator.totp_activate", Result: &result})
	return result, err
}

// @PostRoute("/recovery-codes-issue")
// @SignedIn
func (controller *AuthenticatorController) PostRecoveryCodesIssue(request *http.Request) (AuthenticatorRecoveryCodes, error) {
	var result AuthenticatorRecoveryCodes
	err := controller.authenticatorService.ForCaller(request, EngineCall{Operation: "authenticator.recovery_codes_issue", Result: &result})
	return result, err
}

// @PostRoute("/passkey-register-begin")
// @SignedIn
func (controller *AuthenticatorController) PostPasskeyRegisterBegin(request *http.Request) (AuthenticatorPasskeyChallenge, error) {
	var result AuthenticatorPasskeyChallenge
	err := controller.authenticatorService.ForCaller(request, EngineCall{Operation: "authenticator.passkey_register_begin", Result: &result})
	return result, err
}

// @PostRoute("/passkey-register-finish")
// @SignedIn
func (controller *AuthenticatorController) PostPasskeyRegisterFinish(
	request *http.Request,
	// @FromBody
	body AuthenticatorPasskeyAttestation,
) (AuthenticatorPasskey, error) {
	var result AuthenticatorPasskey
	err := controller.authenticatorService.PasskeyRegisterFinish(request, body, EngineCall{
		Operation: "authenticator.passkey_register_finish",
		Result:    &result,
	})
	return result, err
}

// @PostRoute("/passkey-list")
// @SignedIn
func (controller *AuthenticatorController) PostPasskeyList(request *http.Request) (AuthenticatorPasskeyList, error) {
	var result AuthenticatorPasskeyList
	err := controller.authenticatorService.ForCaller(request, EngineCall{Operation: controller.passkeyListOperation(), Result: &result})
	return result, err
}

// @PostRoute("/passkey-remove")
// @SignedIn
func (controller *AuthenticatorController) PostPasskeyRemove(
	request *http.Request,
	// @FromBody
	body AuthenticatorPasskeyRemoveRequest,
) (AuthenticatorPasskeyRemoval, error) {
	var result AuthenticatorPasskeyRemoval
	err := controller.passkeyService.Remove(request, body, EngineCall{Operation: controller.passkeyRemoveOperation(), Result: &result})
	return result, err
}

// @PostRoute("/set-password-for-principal")
// @Allow(Administrator)
func (controller *AuthenticatorController) PostSetPasswordForPrincipal(
	request *http.Request,
	// @FromBody
	body AuthenticatorSetPasswordRequest,
) (AuthenticatorPasswordSet, error) {
	var result AuthenticatorPasswordSet
	err := controller.principalTenantService.Call(request, body.PrincipalID, EngineCall{
		Operation:  controller.setPasswordOperation(),
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/passkey-list-for-principal")
// @Allow(Administrator)
func (controller *AuthenticatorController) PostPasskeyListForPrincipal(
	request *http.Request,
	// @FromBody
	body PrincipalReference,
) (AuthenticatorPasskeyList, error) {
	var result AuthenticatorPasskeyList
	err := controller.principalTenantService.Call(request, body.PrincipalID, EngineCall{
		Operation:  controller.passkeyListOperation(),
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/passkey-remove-for-principal")
// @Allow(Administrator)
func (controller *AuthenticatorController) PostPasskeyRemoveForPrincipal(
	request *http.Request,
	// @FromBody
	body AuthenticatorPasskeyRemoveForPrincipalRequest,
) (AuthenticatorPasskeyRemoval, error) {
	var result AuthenticatorPasskeyRemoval
	err := controller.passkeyService.RemoveForPrincipal(request, body, EngineCall{Operation: controller.passkeyRemoveOperation(), Result: &result})
	return result, err
}

func (controller *AuthenticatorController) setPasswordOperation() string {
	return "authenticator.set_password"
}

func (controller *AuthenticatorController) passkeyListOperation() string {
	return "authenticator.passkey_list"
}

func (controller *AuthenticatorController) passkeyRemoveOperation() string {
	return "authenticator.passkey_remove"
}
