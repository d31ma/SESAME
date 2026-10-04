type AuthorizeDecideBatchRequest struct {
	Requests      []AuthorizeQuestion `json:"requests"`
	PolicyVersion *int64              `json:"policy_version,omitempty"`
}
