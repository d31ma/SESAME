type AuthorizeSessionBatch struct {
	Requests      []AuthorizeSessionQuestion `json:"requests"`
	PolicyVersion *int64                     `json:"policy_version,omitempty"`
}
