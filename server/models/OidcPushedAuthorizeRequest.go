type OidcPushedAuthorizeRequest struct {
	ClientID            string   `json:"client_id"`
	ClientSecret        string   `json:"client_secret,omitempty"`
	Redirect            string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
}
