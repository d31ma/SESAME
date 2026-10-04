import "net/http"

// @Service
// @NeedsAll
type SessionService struct {
	tenantCallService *TenantCallService
}

func (service *SessionService) RevokeOwn(request *http.Request, body SessionRevokeReason, call EngineCall) error {
	return service.tenantCallService.CallAsCaller(request, func(caller Caller) EngineCall {
		call.Parameters = SessionRevokeRequest{SessionID: caller.SessionID, Reason: body.Reason}
		return call
	})
}
