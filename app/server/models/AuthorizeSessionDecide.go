type AuthorizeSessionDecide struct {
	TenantID      string            `json:"tenant_id"`
	PrincipalID   string            `json:"principal_id"`
	Action        string            `json:"action"`
	Resource      string            `json:"resource"`
	Context       map[string]string `json:"context,omitempty"`
	SessionID     string            `json:"session_id"`
	SessionSecret string            `json:"session_secret"`
	PolicyVersion *int64            `json:"policy_version,omitempty"`
}
