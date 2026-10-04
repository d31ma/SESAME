type OidcConsent struct {
	PrincipalID string   `json:"principal_id"`
	ClientID    string   `json:"client_id"`
	TenantID    string   `json:"tenant_id"`
	Scopes      []string `json:"scopes"`
	GrantedAt   string   `json:"granted_at"`
	Withdrawn   bool     `json:"withdrawn,omitempty"`
}
