type AuthnCompleteRequest struct {
	TransactionID   string `json:"transaction_id"`
	LifetimeSeconds int64  `json:"lifetime_seconds,omitempty"`
}
