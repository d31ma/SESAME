type PrincipalCreateRequest struct {
	TenantID            string `json:"tenant_id"`
	Kind                string `json:"kind"`
	IdentifierNamespace string `json:"identifier_namespace"`
	IdentifierValue     string `json:"identifier_value"`
}
