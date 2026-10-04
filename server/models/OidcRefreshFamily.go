type OidcRefreshFamily struct {
	FamilyID      string `json:"family_id"`
	TenantID      string `json:"tenant_id"`
	ClientID      string `json:"client_id"`
	SessionID     string `json:"session_id"`
	StartedAt     string `json:"started_at"`
	ExpiresAt     string `json:"expires_at"`
	Revoked       bool   `json:"revoked,omitempty"`
	RevokedReason string `json:"revoked_reason,omitempty"`
}
