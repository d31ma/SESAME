type RoleCreateRequest struct {
	TenantID    string           `json:"tenant_id"`
	Name        string           `json:"name"`
	Permissions []RolePermission `json:"permissions"`
}
