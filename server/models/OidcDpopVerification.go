type OidcDpopVerification struct {
	Active      bool     `json:"active"`
	TenantID    string   `json:"tenant_id,omitempty"`
	PrincipalID string   `json:"principal_id,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Thumbprint  string   `json:"dpop_thumbprint,omitempty"`
	ExpiresAt   int64    `json:"expires_at,omitempty"`
}
