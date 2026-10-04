type SamlLoginStartRequest struct {
	TenantID    string `json:"tenant_id"`
	ProviderID  string `json:"provider_id"`
	ConsumerURL string `json:"consumer_url"`
}
