type EngineSettings struct {
	Binary                      string   `json:"binary"`
	Deployment                  string   `json:"deployment"`
	WaitMilliseconds            int64    `json:"waitmilliseconds"`
	SamlConsumerAddresses       []string `json:"samlconsumerurls"`
	FederationRedirectAddresses []string `json:"federationredirecturis"`
}
