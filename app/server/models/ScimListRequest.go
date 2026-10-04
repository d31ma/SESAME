type ScimListRequest struct {
	Filter     string `json:"filter,omitempty"`
	StartIndex int    `json:"start_index,omitempty"`
	Count      int    `json:"count,omitempty"`
}
