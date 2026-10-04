// @HTTPClient({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})
type SesameAuthnClient interface {
	// @PostRequest("/begin")
	Begin(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/complete")
	Complete(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/passkey-options")
	PasskeyOptions(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/verify-passkey")
	VerifyPasskey(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/verify-password")
	VerifyPassword(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/verify-recovery-code")
	VerifyRecoveryCode(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)

	// @PostRequest("/verify-totp")
	VerifyTotp(
		// @RequestBody
		body BehaviorValue,
	) (BehaviorValue, error)
}
