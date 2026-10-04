type AuthorizeDecideRequest struct {
	Action        string            `json:"action"`
	Resource      string            `json:"resource"`
	Context       map[string]string `json:"context,omitempty"`
	PolicyVersion *int64            `json:"policy_version,omitempty"`
}
