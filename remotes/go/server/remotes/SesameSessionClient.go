// @HTTPClient({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})
type SesameSessionClient interface {
	// @PostRequest("/revoke")
	Revoke(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/revoke-by-id")
	RevokeById(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/verify")
	Verify(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
