import "net/http"

// @RequestRoute("/api/v1/session")
// @NeedsAll
type SessionController struct {
	callerService *CallerService
	engineService *EngineService
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
	caller, err := controller.callerService.Resolve(request)
	err = controller.send(controller.ownSession(caller, body), &result, err)
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
	_, err := controller.callerService.Resolve(request)
	err = controller.send(body, &result, err)
	return result, err
}

func (controller *SessionController) ownSession(caller Caller, body SessionRevokeReason) SessionRevokeRequest {
	return SessionRevokeRequest{SessionID: caller.SessionID, Reason: body.Reason}
}

func (controller *SessionController) send(order SessionRevokeRequest, result *SessionRevocation, failure error) error {
	if failure != nil {
		return failure
	}
	return controller.engineService.Call("session.revoke", order, result)
}
