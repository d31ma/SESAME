// @HTTPClient({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})
type SesameTenantClient interface {
	// @PostRequest("/get")
	Get(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
