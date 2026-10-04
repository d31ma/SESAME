type PrincipalGetRequest struct {
	PrincipalID         string `json:"principal_id,omitempty"`
	TenantID            string `json:"tenant_id,omitempty"`
	IdentifierNamespace string `json:"identifier_namespace,omitempty"`
	IdentifierValue     string `json:"identifier_value,omitempty"`
}
