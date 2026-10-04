type AdministratorQuestion struct {
	TenantID      string `json:"tenant_id"`
	PrincipalID   string `json:"principal_id"`
	Action        string `json:"action"`
	Resource      string `json:"resource"`
	SessionID     string `json:"session_id"`
	SessionSecret string `json:"session_secret"`
}
