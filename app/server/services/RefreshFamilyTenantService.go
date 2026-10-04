import "net/http"

// @Service
// @NeedsAll
type RefreshFamilyTenantService struct {
	tenantCallService *TenantCallService
}

func (service *RefreshFamilyTenantService) Call(request *http.Request, familyID string, call EngineCall) error {
	return service.tenantCallService.CallOwned(request, service.lookup(familyID), call)
}

func (service *RefreshFamilyTenantService) lookup(familyID string) EngineCall {
	return EngineCall{
		Operation:  "oidc.refresh_family_get",
		Parameters: OidcRefreshFamilyReference{FamilyID: familyID},
		Result:     &OidcRefreshFamily{},
	}
}
