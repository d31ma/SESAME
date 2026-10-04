// @HTTPClient({"path":"/api/v1/scim","adapter":"sesame","setup":"SesameSetup"})
type SesameScimClient interface {
	// @PostRequest("/client-disable")
	ClientDisable(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/client-register")
	ClientRegister(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/client-rotate-token")
	ClientRotateToken(
		// @RequestHeader("Sesame-Session")
		session BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/group-create")
	GroupCreate(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/group-deprovision")
	GroupDeprovision(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/group-get")
	GroupGet(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/group-list")
	GroupList(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/group-patch")
	GroupPatch(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/user-create")
	UserCreate(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/user-deprovision")
	UserDeprovision(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/user-get")
	UserGet(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/user-list")
	UserList(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/user-patch")
	UserPatch(
		// @RequestHeader("Authorization")
		authorization BehaviorValue,
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
