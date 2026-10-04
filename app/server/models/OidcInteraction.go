type OidcInteraction struct {
	InteractionID string   `json:"interaction_id"`
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	Redirect      string   `json:"redirect_uri"`
	Scopes        []string `json:"scopes"`
	Status        string   `json:"status"`
	ExpiresAt     string   `json:"expires_at"`
}
