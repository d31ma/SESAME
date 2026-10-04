type OidcConsentGrantRequest struct {
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}
