type SamlLogin struct {
	LoginID      string `json:"login_id"`
	AuthnRequest string `json:"authn_request"`
	RedirectURL  string `json:"redirect_url"`
	Destination  string `json:"destination"`
	ExpiresAt    string `json:"expires_at"`
}
