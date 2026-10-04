// @HTTPClient({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})
type SesameGrantClient interface {
	// @PostRequest("/create")
	Create(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/revoke")
	Revoke(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
