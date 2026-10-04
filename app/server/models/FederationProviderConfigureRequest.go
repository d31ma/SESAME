type FederationProviderConfigureRequest struct {
	TenantID          string `json:"tenant_id"`
	ProviderID        string `json:"provider_id"`
	DiscoveryDocument string `json:"discovery_document"`
	KeySetDocument    string `json:"key_set_document"`
}
