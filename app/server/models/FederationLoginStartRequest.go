type FederationLoginStartRequest struct {
	TenantID    string `json:"tenant_id"`
	ProviderID  string `json:"provider_id"`
	RedirectURI string `json:"redirect_uri"`
}
