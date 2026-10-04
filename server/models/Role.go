type Role struct {
	RoleID      string           `json:"role_id"`
	TenantID    string           `json:"tenant_id"`
	Name        string           `json:"name"`
	Permissions []RolePermission `json:"permissions"`
}
