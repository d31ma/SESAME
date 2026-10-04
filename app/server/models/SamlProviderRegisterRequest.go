type SamlProviderRegisterRequest struct {
	TenantID            string   `json:"tenant_id"`
	Name                string   `json:"name"`
	EntityID            string   `json:"entity_id"`
	SignOnURL           string   `json:"sso_url"`
	Certificates        []string `json:"certificates"`
	IdentifierNamespace string   `json:"identifier_namespace,omitempty"`
	Linking             string   `json:"linking,omitempty"`
}
