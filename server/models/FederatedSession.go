type FederatedSession struct {
	SessionID     string `json:"session_id"`
	SessionSecret string `json:"session_secret"`
	TenantID      string `json:"tenant_id"`
	PrincipalID   string `json:"principal_id"`
	ExpiresAt     string `json:"expires_at"`
	Assurance     string `json:"assurance"`
}
