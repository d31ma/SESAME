// @RequestRoute("/api/v1/authn")
// @Public
// @NeedsAll
type AuthnController struct {
	publicCallService *PublicCallService
}

// @PostRoute("/begin")
func (controller *AuthnController) PostBegin(
	// @FromBody
	body AuthnBeginRequest,
) (AuthnTransaction, error) {
	return controller.advance("authn.begin", body)
}

// @PostRoute("/verify-password")
func (controller *AuthnController) PostVerifyPassword(
	// @FromBody
	body AuthnVerifyPasswordRequest,
) (AuthnTransaction, error) {
	return controller.advance("authn.verify_password", body)
}

// @PostRoute("/verify-totp")
func (controller *AuthnController) PostVerifyTotp(
	// @FromBody
	body AuthnCodeRequest,
) (AuthnTransaction, error) {
	return controller.advance("authn.verify_totp", body)
}

// @PostRoute("/verify-recovery-code")
func (controller *AuthnController) PostVerifyRecoveryCode(
	// @FromBody
	body AuthnCodeRequest,
) (AuthnTransaction, error) {
	return controller.advance("authn.verify_recovery_code", body)
}

// @PostRoute("/passkey-options")
func (controller *AuthnController) PostPasskeyOptions(
	// @FromBody
	body AuthnTransactionRequest,
) (AuthnPasskeyOptions, error) {
	var result AuthnPasskeyOptions
	err := controller.publicCallService.Call(EngineCall{Operation: "authn.passkey_options", Parameters: body, Result: &result})
	return result, err
}

// @PostRoute("/verify-passkey")
func (controller *AuthnController) PostVerifyPasskey(
	// @FromBody
	body AuthnVerifyPasskeyRequest,
) (AuthnTransaction, error) {
	return controller.advance("authn.verify_passkey", body)
}

// @PostRoute("/complete")
func (controller *AuthnController) PostComplete(
	// @FromBody
	body AuthnCompleteRequest,
) (AuthnIssuedSession, error) {
	var result AuthnIssuedSession
	err := controller.publicCallService.Call(EngineCall{Operation: "authn.complete", Parameters: body, Result: &result})
	return result, err
}

func (controller *AuthnController) advance(operation string, parameters any) (AuthnTransaction, error) {
	var result AuthnTransaction
	err := controller.publicCallService.Call(EngineCall{Operation: operation, Parameters: parameters, Result: &result})
	return result, err
}
