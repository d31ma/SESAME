type Caller struct {
	TenantID      string `json:"tenant_id"`
	PrincipalID   string `json:"principal_id"`
	SessionID     string `json:"session_id"`
	SessionSecret string `json:"-"`
	IssuedAt      string `json:"issued_at"`
}
