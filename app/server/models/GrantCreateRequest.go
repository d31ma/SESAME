type GrantCreateRequest struct {
	TenantID    string `json:"tenant_id"`
	RoleID      string `json:"role_id"`
	PrincipalID string `json:"principal_id,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
}
