import (
	"net/http"
	"slices"

	"github.com/d31ma/sesame/server/packages/host"
)

// @RequestRoute("/api/v1/authenticator")
// @SignedIn
// @NeedsAll
type AuthenticatorController struct {
	callerService       *CallerService
	engineService       *EngineService
	recentSignInService *RecentSignInService
}

// @PostRoute("/set-password")
func (controller *AuthenticatorController) PostSetPassword(
	request *http.Request,
	// @FromBody
	body AuthenticatorPassword,
) (AuthenticatorPasswordSet, error) {
	var result AuthenticatorPasswordSet
	caller, err := controller.recentCaller(request)
	err = controller.send(err, EngineCall{
		Operation:  "authenticator.set_password",
		Parameters: AuthenticatorSetPasswordRequest{PrincipalID: caller.PrincipalID, Password: body.Password},
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/totp-enroll")
func (controller *AuthenticatorController) PostTotpEnroll(
	request *http.Request,
	// @FromBody
	body AuthenticatorTotpIssuer,
) (AuthenticatorTotpEnrollment, error) {
	var result AuthenticatorTotpEnrollment
	caller, err := controller.recentCaller(request)
	err = controller.send(err, EngineCall{
		Operation:  "authenticator.totp_enroll",
		Parameters: AuthenticatorTotpEnrollRequest{PrincipalID: caller.PrincipalID, Issuer: body.Issuer},
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/totp-activate")
func (controller *AuthenticatorController) PostTotpActivate(
	request *http.Request,
	// @FromBody
	body AuthenticatorTotpCode,
) (AuthenticatorTotpActivation, error) {
	var result AuthenticatorTotpActivation
	caller, err := controller.recentCaller(request)
	err = controller.send(err, EngineCall{
		Operation:  "authenticator.totp_activate",
		Parameters: AuthenticatorTotpActivateRequest{PrincipalID: caller.PrincipalID, Code: body.Code},
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/recovery-codes-issue")
func (controller *AuthenticatorController) PostRecoveryCodesIssue(request *http.Request) (AuthenticatorRecoveryCodes, error) {
	var result AuthenticatorRecoveryCodes
	caller, err := controller.recentCaller(request)
	err = controller.send(err, EngineCall{
		Operation:  "authenticator.recovery_codes_issue",
		Parameters: AuthenticatorPrincipalRequest{PrincipalID: caller.PrincipalID},
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/passkey-register-begin")
func (controller *AuthenticatorController) PostPasskeyRegisterBegin(request *http.Request) (AuthenticatorPasskeyChallenge, error) {
	var result AuthenticatorPasskeyChallenge
	caller, err := controller.recentCaller(request)
	err = controller.send(err, EngineCall{
		Operation:  "authenticator.passkey_register_begin",
		Parameters: AuthenticatorPrincipalRequest{PrincipalID: caller.PrincipalID},
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/passkey-register-finish")
func (controller *AuthenticatorController) PostPasskeyRegisterFinish(
	request *http.Request,
	// @FromBody
	body AuthenticatorPasskeyAttestation,
) (AuthenticatorPasskey, error) {
	var result AuthenticatorPasskey
	caller, err := controller.recentCaller(request)
	err = controller.send(err, EngineCall{
		Operation: "authenticator.passkey_register_finish",
		Parameters: AuthenticatorPasskeyRegisterFinishRequest{
			PrincipalID:       caller.PrincipalID,
			AttestationObject: body.AttestationObject,
			ClientDataJSON:    body.ClientDataJSON,
		},
		Result: &result,
	})
	return result, err
}

// @PostRoute("/passkey-list")
func (controller *AuthenticatorController) PostPasskeyList(request *http.Request) (AuthenticatorPasskeyList, error) {
	caller, err := controller.callerService.Resolve(request)
	return controller.passkeys(caller.PrincipalID, err)
}

// @PostRoute("/passkey-remove")
func (controller *AuthenticatorController) PostPasskeyRemove(
	request *http.Request,
	// @FromBody
	body AuthenticatorPasskeyRemoveRequest,
) (AuthenticatorPasskeyRemoval, error) {
	var result AuthenticatorPasskeyRemoval
	caller, err := controller.recentCaller(request)
	owned, err := controller.passkeys(caller.PrincipalID, err)
	err = controller.requireOwned(controller.credentialIdentifiers(owned), body.CredentialID, err)
	err = controller.send(err, EngineCall{Operation: "authenticator.passkey_remove", Parameters: body, Result: &result})
	return result, err
}

func (controller *AuthenticatorController) recentCaller(request *http.Request) (Caller, error) {
	caller, err := controller.callerService.Resolve(request)
	return caller, controller.recentSignInService.Require(caller, err)
}

func (controller *AuthenticatorController) passkeys(principalID string, failure error) (AuthenticatorPasskeyList, error) {
	var result AuthenticatorPasskeyList
	failure = controller.send(failure, EngineCall{
		Operation:  "authenticator.passkey_list",
		Parameters: AuthenticatorPrincipalRequest{PrincipalID: principalID},
		Result:     &result,
	})
	return result, failure
}

func (controller *AuthenticatorController) credentialIdentifiers(owned AuthenticatorPasskeyList) []string {
	identifiers := []string{}
	for _, passkey := range owned.Passkeys {
		identifiers = append(identifiers, passkey.CredentialID)
	}
	return identifiers
}

func (controller *AuthenticatorController) requireOwned(identifiers []string, credentialID string, failure error) error {
	if failure != nil || slices.Contains(identifiers, credentialID) {
		return failure
	}
	return &host.PasskeyNotFoundError{}
}

func (controller *AuthenticatorController) send(failure error, call EngineCall) error {
	if failure != nil {
		return failure
	}
	return controller.engineService.Call(call.Operation, call.Parameters, call.Result)
}
