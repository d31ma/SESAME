type FederationProviderView struct {
	Provider              FederationProvider `json:"provider"`
	Configured            bool               `json:"configured"`
	AuthorizationEndpoint string             `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string             `json:"token_endpoint,omitempty"`
	KeySetURL             string             `json:"jwks_uri,omitempty"`
	KeyCount              int                `json:"key_count,omitempty"`
}
