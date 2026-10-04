// @RequestRoute("/api/v1/authn")
// @Public
// @NeedsAll
type AuthnController struct {
	engineService *EngineService
}

// @PostRoute("/begin")
func (controller *AuthnController) PostBegin(
	// @FromBody
	body AuthnBeginRequest,
) (AuthnTransaction, error) {
	var result AuthnTransaction
	err := controller.engineService.Call("authn.begin", body, &result)
	return result, err
}

// @PostRoute("/verify-password")
func (controller *AuthnController) PostVerifyPassword(
	// @FromBody
	body AuthnVerifyPasswordRequest,
) (AuthnTransaction, error) {
	var result AuthnTransaction
	err := controller.engineService.Call("authn.verify_password", body, &result)
	return result, err
}

// @PostRoute("/verify-totp")
func (controller *AuthnController) PostVerifyTotp(
	// @FromBody
	body AuthnCodeRequest,
) (AuthnTransaction, error) {
	var result AuthnTransaction
	err := controller.engineService.Call("authn.verify_totp", body, &result)
	return result, err
}

// @PostRoute("/verify-recovery-code")
func (controller *AuthnController) PostVerifyRecoveryCode(
	// @FromBody
	body AuthnCodeRequest,
) (AuthnTransaction, error) {
	var result AuthnTransaction
	err := controller.engineService.Call("authn.verify_recovery_code", body, &result)
	return result, err
}

// @PostRoute("/passkey-options")
func (controller *AuthnController) PostPasskeyOptions(
	// @FromBody
	body AuthnTransactionRequest,
) (AuthnPasskeyOptions, error) {
	var result AuthnPasskeyOptions
	err := controller.engineService.Call("authn.passkey_options", body, &result)
	return result, err
}

// @PostRoute("/verify-passkey")
func (controller *AuthnController) PostVerifyPasskey(
	// @FromBody
	body AuthnVerifyPasskeyRequest,
) (AuthnTransaction, error) {
	var result AuthnTransaction
	err := controller.engineService.Call("authn.verify_passkey", body, &result)
	return result, err
}

// @PostRoute("/complete")
func (controller *AuthnController) PostComplete(
	// @FromBody
	body AuthnCompleteRequest,
) (AuthnIssuedSession, error) {
	var result AuthnIssuedSession
	err := controller.engineService.Call("authn.complete", body, &result)
	return result, err
}
