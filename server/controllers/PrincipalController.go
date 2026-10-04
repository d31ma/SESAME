import (
	"net/http"
	"slices"

	"github.com/d31ma/sesame/server/packages/host"
)

// @RequestRoute("/api/v1/principal")
// @Allow(Administrator)
// @NeedsAll
type PrincipalController struct {
	tenantCallService      *TenantCallService
	principalTenantService *PrincipalTenantService
}

// @PostRoute("/create")
func (controller *PrincipalController) PostCreate(
	request *http.Request,
	// @FromBody
	body PrincipalCreateRequest,
) (Principal, error) {
	var result Principal
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "principal.create",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/get")
func (controller *PrincipalController) PostGet(
	request *http.Request,
	// @FromBody
	body PrincipalGetRequest,
) (Principal, error) {
	failure := controller.oneLookupForm(body)
	lookup := controller.lookupFor(body)
	return lookup(request, body, failure)
}

func (controller *PrincipalController) oneLookupForm(body PrincipalGetRequest) error {
	forms := []bool{body.PrincipalID != "", controller.namesIdentifier(body)}
	if !slices.Contains(forms, false) {
		return &host.MixedPrincipalLookupError{}
	}
	return nil
}

func (controller *PrincipalController) lookupFor(
	body PrincipalGetRequest,
) func(request *http.Request, body PrincipalGetRequest, failure error) (Principal, error) {
	if controller.namesIdentifier(body) {
		return controller.getInTenant
	}
	return controller.getByID
}

func (controller *PrincipalController) namesIdentifier(body PrincipalGetRequest) bool {
	named := []bool{body.TenantID != "", body.IdentifierNamespace != "", body.IdentifierValue != ""}
	return slices.Contains(named, true)
}

func (controller *PrincipalController) getByID(request *http.Request, body PrincipalGetRequest, failure error) (Principal, error) {
	if failure != nil {
		return Principal{}, failure
	}
	return controller.principalTenantService.Require(request, body.PrincipalID)
}

func (controller *PrincipalController) getInTenant(request *http.Request, body PrincipalGetRequest, failure error) (Principal, error) {
	if failure != nil {
		return Principal{}, failure
	}
	var result Principal
	err := controller.tenantCallService.Call(request, body.TenantID, EngineCall{
		Operation:  "principal.get",
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

// @PostRoute("/suspend")
func (controller *PrincipalController) PostSuspend(
	request *http.Request,
	// @FromBody
	body PrincipalReference,
) (Principal, error) {
	var result Principal
	err := controller.principalTenantService.Call(request, body.PrincipalID, EngineCall{
		Operation:  "principal.suspend",
		Parameters: body,
		Result:     &result,
		Privileged: true,
	})
	return result, err
}
