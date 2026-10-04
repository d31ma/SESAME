import (
	"net/http"
	"slices"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @RequestRoute("/api/v1/authenticator")
// @NeedsAll
type AuthenticatorController struct {
	tenantCallService      *TenantCallService
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
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		parameters := AuthenticatorSetPasswordRequest{PrincipalID: caller.PrincipalID, Password: body.Password}
		return controller.change(controller.setPasswordOperation(), parameters, &result)
	})
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
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		parameters := AuthenticatorTotpEnrollRequest{PrincipalID: caller.PrincipalID, Issuer: body.Issuer}
		return controller.change("authenticator.totp_enroll", parameters, &result)
	})
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
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		parameters := AuthenticatorTotpActivateRequest{PrincipalID: caller.PrincipalID, Code: body.Code}
		return controller.change("authenticator.totp_activate", parameters, &result)
	})
	return result, err
}

// @PostRoute("/recovery-codes-issue")
// @SignedIn
func (controller *AuthenticatorController) PostRecoveryCodesIssue(request *http.Request) (AuthenticatorRecoveryCodes, error) {
	var result AuthenticatorRecoveryCodes
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		return controller.change("authenticator.recovery_codes_issue", PrincipalReference{PrincipalID: caller.PrincipalID}, &result)
	})
	return result, err
}

// @PostRoute("/passkey-register-begin")
// @SignedIn
func (controller *AuthenticatorController) PostPasskeyRegisterBegin(request *http.Request) (AuthenticatorPasskeyChallenge, error) {
	var result AuthenticatorPasskeyChallenge
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		return controller.change("authenticator.passkey_register_begin", PrincipalReference{PrincipalID: caller.PrincipalID}, &result)
	})
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
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		return controller.change("authenticator.passkey_register_finish", AuthenticatorPasskeyRegisterFinishRequest{
			PrincipalID:       caller.PrincipalID,
			AttestationObject: body.AttestationObject,
			ClientDataJSON:    body.ClientDataJSON,
		}, &result)
	})
	return result, err
}

// @PostRoute("/passkey-list")
// @SignedIn
func (controller *AuthenticatorController) PostPasskeyList(request *http.Request) (AuthenticatorPasskeyList, error) {
	var result AuthenticatorPasskeyList
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		return controller.passkeyListing(caller.PrincipalID, &result)
	})
	return result, err
}

// @PostRoute("/passkey-remove")
// @SignedIn
func (controller *AuthenticatorController) PostPasskeyRemove(
	request *http.Request,
	// @FromBody
	body AuthenticatorPasskeyRemoveRequest,
) (AuthenticatorPasskeyRemoval, error) {
	var owned AuthenticatorPasskeyList
	var result AuthenticatorPasskeyRemoval
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		return controller.privileged(controller.passkeyListing(caller.PrincipalID, &owned))
	})
	err = controller.requireOwned(owned, body.CredentialID, err)
	err = controller.afterwards(err, func() error {
		return controller.tenantCallService.CallAsCaller(request, func(Caller) EngineCall {
			return controller.passkeyRemoval(body.CredentialID, &result)
		})
	})
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
	err := controller.principalTenantService.Call(request, body.PrincipalID, controller.change(controller.setPasswordOperation(), body, &result))
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
	err := controller.principalTenantService.Call(request, body.PrincipalID, controller.passkeyListing(body.PrincipalID, &result))
	return result, err
}

// @PostRoute("/passkey-remove-for-principal")
// @Allow(Administrator)
func (controller *AuthenticatorController) PostPasskeyRemoveForPrincipal(
	request *http.Request,
	// @FromBody
	body AuthenticatorPasskeyRemoveForPrincipalRequest,
) (AuthenticatorPasskeyRemoval, error) {
	var owned AuthenticatorPasskeyList
	var result AuthenticatorPasskeyRemoval
	listing := controller.privileged(controller.passkeyListing(body.PrincipalID, &owned))
	err := controller.principalTenantService.Call(request, body.PrincipalID, listing)
	err = controller.requireOwned(owned, body.CredentialID, err)
	err = controller.afterwards(err, func() error {
		return controller.principalTenantService.Call(request, body.PrincipalID, controller.passkeyRemoval(body.CredentialID, &result))
	})
	return result, err
}

func (controller *AuthenticatorController) change(operation string, parameters any, result any) EngineCall {
	return EngineCall{Operation: operation, Parameters: parameters, Result: result, Privileged: true}
}

func (controller *AuthenticatorController) privileged(call EngineCall) EngineCall {
	call.Privileged = true
	return call
}

func (controller *AuthenticatorController) passkeyListing(principalID string, result *AuthenticatorPasskeyList) EngineCall {
	return EngineCall{
		Operation:  "authenticator.passkey_list",
		Parameters: PrincipalReference{PrincipalID: principalID},
		Result:     result,
	}
}

func (controller *AuthenticatorController) passkeyRemoval(credentialID string, result *AuthenticatorPasskeyRemoval) EngineCall {
	return controller.change("authenticator.passkey_remove", AuthenticatorPasskeyRemoveRequest{CredentialID: credentialID}, result)
}

func (controller *AuthenticatorController) requireOwned(owned AuthenticatorPasskeyList, credentialID string, failure error) error {
	if failure != nil || slices.Contains(controller.credentialIdentifiers(owned), credentialID) {
		return failure
	}
	return &host.PasskeyNotFoundError{}
}

func (controller *AuthenticatorController) credentialIdentifiers(owned AuthenticatorPasskeyList) []string {
	identifiers := []string{}
	for _, passkey := range owned.Passkeys {
		identifiers = append(identifiers, passkey.CredentialID)
	}
	return identifiers
}

func (controller *AuthenticatorController) afterwards(failure error, next func() error) error {
	if failure != nil {
		return failure
	}
	return next()
}

func (controller *AuthenticatorController) setPasswordOperation() string {
	return "authenticator.set_password"
}
