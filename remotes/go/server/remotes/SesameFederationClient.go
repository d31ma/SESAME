// @HTTPClient({"path":"/api/v1/federation","adapter":"sesame","setup":"SesameSetup"})
type SesameFederationClient interface {
	// @PostRequest("/login-complete")
	LoginComplete(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/login-start")
	LoginStart(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/provider-configure")
	ProviderConfigure(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/provider-disable")
	ProviderDisable(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/provider-get")
	ProviderGet(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/provider-register")
	ProviderRegister(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
