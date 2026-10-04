type AuthorizeQuestion struct {
	Action   string            `json:"action"`
	Resource string            `json:"resource"`
	Context  map[string]string `json:"context,omitempty"`
}
