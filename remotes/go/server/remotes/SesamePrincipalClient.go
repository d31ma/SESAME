// @HTTPClient({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})
type SesamePrincipalClient interface {
	// @PostRequest("/create")
	Create(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/get")
	Get(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/suspend")
	Suspend(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
