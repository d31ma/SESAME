type AuthorizeDecision struct {
	DecisionID        string `json:"decision_id"`
	Decision          string `json:"decision"`
	ReasonCode        string `json:"reason_code"`
	PolicyVersion     int64  `json:"policy_version"`
	MissingContextKey string `json:"missing_context_key,omitempty"`
}
