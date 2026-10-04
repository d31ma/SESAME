import (
	"net/http"
	"slices"

	"github.com/d31ma/sesame/app/server/packages/host"
)

// @Service
// @NeedsAll
type PrincipalLookupService struct {
	tenantCallService      *TenantCallService
	principalTenantService *PrincipalTenantService
}

func (service *PrincipalLookupService) Get(request *http.Request, body PrincipalGetRequest, call EngineCall) (Principal, error) {
	failure := service.oneLookupForm(body)
	lookup := service.lookupFor(body)
	return lookup(request, body, call, failure)
}

func (service *PrincipalLookupService) oneLookupForm(body PrincipalGetRequest) error {
	forms := []bool{body.PrincipalID != "", service.namesIdentifier(body)}
	if !slices.Contains(forms, false) {
		return &host.MixedPrincipalLookupError{}
	}
	return nil
}

func (service *PrincipalLookupService) lookupFor(
	body PrincipalGetRequest,
) func(request *http.Request, body PrincipalGetRequest, call EngineCall, failure error) (Principal, error) {
	if service.namesIdentifier(body) {
		return service.getInTenant
	}
	return service.getByID
}

func (service *PrincipalLookupService) namesIdentifier(body PrincipalGetRequest) bool {
	named := []bool{body.TenantID != "", body.IdentifierNamespace != "", body.IdentifierValue != ""}
	return slices.Contains(named, true)
}

func (service *PrincipalLookupService) getByID(
	request *http.Request,
	body PrincipalGetRequest,
	_ EngineCall,
	failure error,
) (Principal, error) {
	if failure != nil {
		return Principal{}, failure
	}
	return service.principalTenantService.Require(request, body.PrincipalID)
}

func (service *PrincipalLookupService) getInTenant(
	request *http.Request,
	body PrincipalGetRequest,
	call EngineCall,
	failure error,
) (Principal, error) {
	if failure != nil {
		return Principal{}, failure
	}
	result := Principal{}
	call.Result = &result
	failure = service.tenantCallService.Call(request, body.TenantID, call)
	return result, failure
}
