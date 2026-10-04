type ScimEngineCall struct {
	Token      string `json:"token"`
	ResourceID string `json:"resource_id,omitempty"`
	Body       string `json:"body,omitempty"`
	Filter     string `json:"filter,omitempty"`
	StartIndex int    `json:"start_index,omitempty"`
	Count      int    `json:"count,omitempty"`
}
