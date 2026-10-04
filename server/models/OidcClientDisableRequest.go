type OidcClientDisableRequest struct {
	ClientID string `json:"client_id"`
	Reason   string `json:"reason,omitempty"`
}
