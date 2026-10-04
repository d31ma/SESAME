type OidcClientRegisterRequest struct {
	TenantID            string   `json:"tenant_id"`
	Name                string   `json:"name"`
	ClientType          string   `json:"client_type"`
	Redirects           []string `json:"redirect_uris"`
	Scopes              []string `json:"scopes,omitempty"`
	Audience            string   `json:"audience,omitempty"`
	PostLogoutRedirects []string `json:"post_logout_redirect_uris,omitempty"`
}
