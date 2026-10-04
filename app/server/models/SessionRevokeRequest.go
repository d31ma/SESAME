type SessionRevokeRequest struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason,omitempty"`
}
