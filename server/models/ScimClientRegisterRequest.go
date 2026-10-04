type ScimClientRegisterRequest struct {
	TenantID            string `json:"tenant_id"`
	Name                string `json:"name"`
	IdentifierNamespace string `json:"identifier_namespace,omitempty"`
	CanManageGroups     bool   `json:"can_manage_groups,omitempty"`
}
