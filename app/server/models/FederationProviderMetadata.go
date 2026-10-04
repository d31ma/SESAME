type FederationProviderMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	KeySetURL             string   `json:"jwks_uri"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	ResponseTypes         []string `json:"response_types_supported,omitempty"`
	SigningAlgorithms     []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ChallengeMethods      []string `json:"code_challenge_methods_supported,omitempty"`
}
