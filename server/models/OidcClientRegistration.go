type OidcClientRegistration struct {
	Client       OidcClient `json:"client"`
	ClientSecret string     `json:"client_secret,omitempty"`
}
