// @HTTPClient({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})
type SesameGroupClient interface {
	// @PostRequest("/create")
	Create(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/member-add")
	MemberAdd(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/member-remove")
	MemberRemove(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
