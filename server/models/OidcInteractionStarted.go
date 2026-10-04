type OidcInteractionStarted struct {
	InteractionID string   `json:"interaction_id"`
	ClientID      string   `json:"client_id"`
	ClientName    string   `json:"client_name"`
	Scopes        []string `json:"scopes"`
	ExpiresAt     string   `json:"expires_at"`
}
