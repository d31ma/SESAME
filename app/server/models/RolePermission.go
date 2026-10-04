type RolePermission struct {
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	Conditions map[string]string `json:"conditions,omitempty"`
}
