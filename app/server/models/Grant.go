type Grant struct {
	GrantID     string `json:"grant_id"`
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
	RoleID      string `json:"role_id"`
}
