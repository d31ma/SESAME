type VerifiedSession struct {
	SessionID   string `json:"session_id"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	Status      string `json:"status"`
}
