import (
	"net/http"
	"slices"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Service
// @NeedsAll
type PasskeyService struct {
	tenantCallService      *TenantCallService
	principalTenantService *PrincipalTenantService
}

func (service *PasskeyService) Remove(request *http.Request, body AuthenticatorPasskeyRemoveRequest, call EngineCall) error {
	owned, failure := service.ownedByCaller(request)
	failure = service.requireOwned(owned, body.CredentialID, failure)
	return service.removeAsCaller(request, service.removal(body.CredentialID, call), failure)
}

func (service *PasskeyService) RemoveForPrincipal(
	request *http.Request,
	body AuthenticatorPasskeyRemoveForPrincipalRequest,
	call EngineCall,
) error {
	owned := AuthenticatorPasskeyList{}
	failure := service.principalTenantService.Call(request, body.PrincipalID, service.listing(body.PrincipalID, &owned))
	failure = service.requireOwned(owned, body.CredentialID, failure)
	return service.removeForPrincipal(request, body.PrincipalID, service.removal(body.CredentialID, call), failure)
}

func (service *PasskeyService) ownedByCaller(request *http.Request) (AuthenticatorPasskeyList, error) {
	owned := AuthenticatorPasskeyList{}
	failure := service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		return service.listing(caller.PrincipalID, &owned)
	})
	return owned, failure
}

func (service *PasskeyService) removeAsCaller(request *http.Request, removal EngineCall, failure error) error {
	if failure != nil {
		return failure
	}
	return service.tenantCallService.CallAsCaller(request, func(Caller) EngineCall {
		return removal
	})
}

func (service *PasskeyService) removeForPrincipal(
	request *http.Request,
	principalID string,
	removal EngineCall,
	failure error,
) error {
	if failure != nil {
		return failure
	}
	return service.principalTenantService.Call(request, principalID, removal)
}

func (service *PasskeyService) listing(principalID string, result *AuthenticatorPasskeyList) EngineCall {
	return EngineCall{
		Operation:  "authenticator.passkey_list",
		Parameters: PrincipalReference{PrincipalID: principalID},
		Result:     result,
		Privileged: true,
	}
}

func (service *PasskeyService) removal(credentialID string, call EngineCall) EngineCall {
	call.Parameters = AuthenticatorPasskeyRemoveRequest{CredentialID: credentialID}
	return call
}

func (service *PasskeyService) requireOwned(owned AuthenticatorPasskeyList, credentialID string, failure error) error {
	if failure != nil || slices.Contains(service.credentialIdentifiers(owned), credentialID) {
		return failure
	}
	return &host.PasskeyNotFoundError{}
}

func (service *PasskeyService) credentialIdentifiers(owned AuthenticatorPasskeyList) []string {
	identifiers := []string{}
	for _, passkey := range owned.Passkeys {
		identifiers = append(identifiers, passkey.CredentialID)
	}
	return identifiers
}
