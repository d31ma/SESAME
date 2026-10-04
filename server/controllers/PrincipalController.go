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
	return controller.get(request, body)
}

func (controller *PrincipalController) get(request *http.Request, body PrincipalGetRequest) (Principal, error) {
	if !controller.namesIdentifier(body) {
		return controller.principalTenantService.Require(request, body.PrincipalID)
	}
	return controller.getByIdentifier(request, body)
}

func (controller *PrincipalController) getByIdentifier(request *http.Request, body PrincipalGetRequest) (Principal, error) {
	if body.PrincipalID != "" {
		return Principal{}, &host.MixedPrincipalLookupError{}
	}
	return controller.getInTenant(request, body)
}

func (controller *PrincipalController) namesIdentifier(body PrincipalGetRequest) bool {
	named := []bool{body.TenantID != "", body.IdentifierNamespace != "", body.IdentifierValue != ""}
	return slices.Contains(named, true)
}

func (controller *PrincipalController) getInTenant(request *http.Request, body PrincipalGetRequest) (Principal, error) {
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
	})
	return result, err
}
