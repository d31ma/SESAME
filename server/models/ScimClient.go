type ScimClient struct {
	ScimClientID        string `json:"scim_client_id"`
	TenantID            string `json:"tenant_id"`
	Name                string `json:"name"`
	CanManageGroups     bool   `json:"can_manage_groups"`
	IdentifierNamespace string `json:"identifier_namespace"`
	Disabled            bool   `json:"disabled,omitempty"`
}
