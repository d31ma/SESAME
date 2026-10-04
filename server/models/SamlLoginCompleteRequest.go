type SamlLoginCompleteRequest struct {
	TenantID  string `json:"tenant_id"`
	LoginID   string `json:"login_id"`
	Assertion string `json:"assertion"`
}
