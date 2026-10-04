// @HTTPClient({"path":"/api/v1/role","adapter":"sesame","setup":"SesameSetup"})
type SesameRoleClient interface {
	// @PostRequest("/create")
	Create(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
