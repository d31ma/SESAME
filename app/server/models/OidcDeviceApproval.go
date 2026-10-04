type OidcDeviceApproval struct {
	TenantID      string `json:"tenant_id"`
	UserCode      string `json:"user_code"`
	SessionID     string `json:"session_id"`
	SessionSecret string `json:"session_secret"`
}
