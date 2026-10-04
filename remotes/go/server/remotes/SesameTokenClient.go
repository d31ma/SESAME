// @HTTPClient({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})
type SesameTokenClient interface {
	// @PostRequest("/jwks")
	Jwks(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
