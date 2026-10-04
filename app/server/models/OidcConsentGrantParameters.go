type OidcConsentGrantParameters struct {
	SessionID     string   `json:"session_id"`
	SessionSecret string   `json:"session_secret"`
	ClientID      string   `json:"client_id"`
	Scopes        []string `json:"scopes"`
}
