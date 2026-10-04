type FederationLogin struct {
	LoginID          string `json:"login_id"`
	AuthorizationURL string `json:"authorization_url"`
	ExpiresAt        string `json:"expires_at"`
}
