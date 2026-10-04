type ProviderDisableRequest struct {
	TenantID   string `json:"tenant_id"`
	ProviderID string `json:"provider_id"`
	Reason     string `json:"reason,omitempty"`
}
