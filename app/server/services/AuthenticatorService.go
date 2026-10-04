import "net/http"

// @Service
// @NeedsAll
type AuthenticatorService struct {
	tenantCallService *TenantCallService
}

func (service *AuthenticatorService) SetPassword(request *http.Request, body AuthenticatorPassword, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = AuthenticatorSetPasswordRequest{PrincipalID: caller.PrincipalID, Password: body.Password}
		return call
	})
}

func (service *AuthenticatorService) TotpEnroll(request *http.Request, body AuthenticatorTotpIssuer, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = AuthenticatorTotpEnrollRequest{PrincipalID: caller.PrincipalID, Issuer: body.Issuer}
		return call
	})
}

func (service *AuthenticatorService) TotpActivate(request *http.Request, body AuthenticatorTotpCode, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = AuthenticatorTotpActivateRequest{PrincipalID: caller.PrincipalID, Code: body.Code}
		return call
	})
}

func (service *AuthenticatorService) PasskeyRegisterFinish(
	request *http.Request,
	body AuthenticatorPasskeyAttestation,
	call EngineCall,
) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = AuthenticatorPasskeyRegisterFinishRequest{
			PrincipalID:       caller.PrincipalID,
			AttestationObject: body.AttestationObject,
			ClientDataJSON:    body.ClientDataJSON,
		}
		return call
	})
}

func (service *AuthenticatorService) ForCaller(request *http.Request, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = PrincipalReference{PrincipalID: caller.PrincipalID}
		return call
	})
}
