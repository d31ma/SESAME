// @HTTPClient({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})
type SesameStandardsClient interface {
	// @GetRequest("/jwks")
	Jwks() (BehaviorValue, error)

	// @GetRequest("/openid-configuration")
	OpenidConfiguration() (BehaviorValue, error)
}
