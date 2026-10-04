type FederationLoginCompleteRequest struct {
	TenantID string `json:"tenant_id"`
	LoginID  string `json:"login_id"`
	IDToken  string `json:"id_token"`
}
