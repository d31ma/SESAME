type FederationProviderRegistration struct {
	Provider FederationProvider       `json:"provider"`
	Fetch    FederationDiscoveryFetch `json:"fetch"`
}
