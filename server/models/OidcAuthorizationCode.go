type OidcAuthorizationCode struct {
	Redirect string `json:"redirect_uri"`
	Code     string `json:"code"`
	State    string `json:"state,omitempty"`
}
