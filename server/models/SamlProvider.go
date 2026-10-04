type SamlProvider struct {
	ProviderID          string   `json:"provider_id"`
	TenantID            string   `json:"tenant_id"`
	Name                string   `json:"name"`
	EntityID            string   `json:"entity_id"`
	SignOnURL           string   `json:"sso_url"`
	Certificates        []string `json:"certificates"`
	IdentifierNamespace string   `json:"identifier_namespace"`
	Linking             string   `json:"linking"`
	Disabled            bool     `json:"disabled,omitempty"`
}
