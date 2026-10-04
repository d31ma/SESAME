type AuthnBeginRequest struct {
	TenantID            string `json:"tenant_id"`
	IdentifierNamespace string `json:"identifier_namespace"`
	IdentifierValue     string `json:"identifier_value"`
}
