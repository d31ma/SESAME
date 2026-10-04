import "net/http"

// @RequestRoute("/api/v1/session")
// @NeedsAll
type SessionController struct {
	engineService     *EngineService
	tenantCallService *TenantCallService
}

// @PostRoute("/verify")
// @Public
func (controller *SessionController) PostVerify(
	// @FromBody
	body SessionCredential,
) (Session, error) {
	var result Session
	err := controller.engineService.Call("session.verify", body, &result)
	return result, err
}

// @PostRoute("/revoke")
// @SignedIn
func (controller *SessionController) PostRevoke(
	request *http.Request,
	// @FromBody
	body SessionRevokeReason,
) (SessionRevocation, error) {
	var result SessionRevocation
	err := controller.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		order := SessionRevokeRequest{SessionID: caller.SessionID, Reason: body.Reason}
		return EngineCall{Operation: controller.revokeOperation(), Parameters: order, Result: &result}
	})
	return result, err
}

// @PostRoute("/revoke-by-id")
// @Allow(Administrator)
func (controller *SessionController) PostRevokeByID(
	request *http.Request,
	// @FromBody
	body SessionRevokeRequest,
) (SessionRevocation, error) {
	var result SessionRevocation
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
