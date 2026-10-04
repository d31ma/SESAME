type OidcClient struct {
	ClientID            string   `json:"client_id"`
	TenantID            string   `json:"tenant_id"`
	Name                string   `json:"name"`
	ClientType          string   `json:"client_type"`
	Redirects           []string `json:"redirect_uris"`
	Scopes              []string `json:"scopes"`
	Audience            string   `json:"audience"`
	PostLogoutRedirects []string `json:"post_logout_redirect_uris,omitempty"`
	Disabled            bool     `json:"disabled,omitempty"`
}
