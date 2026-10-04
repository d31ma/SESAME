import "net/http"

// @RequestRoute("/api/v1/session")
// @NeedsAll
type SessionController struct {
	publicCallService *PublicCallService
	sessionService    *SessionService
	tenantCallService *TenantCallService
}

// @PostRoute("/verify")
// @Public
func (controller *SessionController) PostVerify(
	// @FromBody
	body SessionCredential,
) (Session, error) {
	var result Session
	err := controller.publicCallService.Call(EngineCall{Operation: "session.verify", Parameters: body, Result: &result})
	return result, err
}

// @PostRoute("/revoke")
// @SignedIn
func (controller *SessionController) PostRevoke(
	request *http.Request,
	// @FromBody
	body SessionRevokeReason,
) (RevokeOutcome, error) {
	var result RevokeOutcome
	err := controller.sessionService.RevokeOwn(request, body, EngineCall{Operation: controller.revokeOperation(), Result: &result})
	return result, err
}

// @PostRoute("/revoke-by-id")
// @Allow(Administrator)
func (controller *SessionController) PostRevokeByID(
	request *http.Request,
	// @FromBody
	body SessionRevokeRequest,
) (RevokeOutcome, error) {
	var result RevokeOutcome
	err := controller.tenantCallService.CallAsAdministrator(request, EngineCall{
		Operation:  controller.revokeOperation(),
		Parameters: body,
		Result:     &result,
	})
	return result, err
}

func (controller *SessionController) revokeOperation() string {
	return "session.revoke"
}
