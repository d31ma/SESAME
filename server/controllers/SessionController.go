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
	err = controller.revoke(caller, body, &result, err)
	return result, err
}

func (controller *SessionController) revoke(
	caller Caller,
	body SessionRevokeReason,
	result *SessionRevocation,
	failure error,
) error {
	if failure != nil {
		return failure
	}
	order := SessionRevokeRequest{SessionID: caller.SessionID, Reason: body.Reason}
	return controller.engineService.Call("session.revoke", order, result)
}
