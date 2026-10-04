@HTTPClient({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})
interface SesameAuthnClient {
    @PostRequest("/begin")
    fun begin(@RequestBody body: Any?): Any?

    @PostRequest("/complete")
    fun complete(@RequestBody body: Any?): Any?

    @PostRequest("/passkey-options")
    fun passkeyOptions(@RequestBody body: Any?): Any?

    @PostRequest("/verify-passkey")
    fun verifyPasskey(@RequestBody body: Any?): Any?

    @PostRequest("/verify-password")
    fun verifyPassword(@RequestBody body: Any?): Any?

    @PostRequest("/verify-recovery-code")
    fun verifyRecoveryCode(@RequestBody body: Any?): Any?

    @PostRequest("/verify-totp")
    fun verifyTotp(@RequestBody body: Any?): Any?
}
