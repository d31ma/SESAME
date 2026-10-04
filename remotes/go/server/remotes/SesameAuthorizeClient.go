// @HTTPClient({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})
type SesameAuthorizeClient interface {
	// @PostRequest("/decide")
	Decide(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/decide-batch")
	DecideBatch(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
