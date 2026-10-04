type OidcDeviceAuthorizeRequest struct {
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}
