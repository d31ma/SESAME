@HTTPClient({"path":"/api/v1/authenticator","adapter":"sesame","setup":"SesameSetup"})
interface SesameAuthenticatorClient {
    @PostRequest("/passkey-list")
    fun passkeyList(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/passkey-list-for-principal")
    fun passkeyListForPrincipal(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/passkey-register-begin")
    fun passkeyRegisterBegin(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/passkey-register-finish")
    fun passkeyRegisterFinish(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/passkey-remove")
    fun passkeyRemove(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/passkey-remove-for-principal")
    fun passkeyRemoveForPrincipal(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/recovery-codes-issue")
    fun recoveryCodesIssue(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/set-password")
    fun setPassword(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/set-password-for-principal")
    fun setPasswordForPrincipal(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/totp-activate")
    fun totpActivate(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/totp-enroll")
    fun totpEnroll(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
