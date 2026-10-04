// @HTTPClient({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})
type SesameSystemClient interface {
	// @PostRequest("/build")
	Build(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/metrics")
	Metrics(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/ping")
	Ping(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/readiness")
	Readiness(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/version")
	Version(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
