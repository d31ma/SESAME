type AuthnTransaction struct {
	TransactionID string `json:"transaction_id"`
	State         string `json:"state"`
	Assurance     string `json:"assurance,omitempty"`
	FailureCode   string `json:"failure_code,omitempty"`
	AttemptsLeft  int    `json:"attempts_left"`
}
