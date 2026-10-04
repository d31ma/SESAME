type ScimClientDisableRequest struct {
	TenantID     string `json:"tenant_id"`
	ScimClientID string `json:"scim_client_id"`
	Reason       string `json:"reason,omitempty"`
}
