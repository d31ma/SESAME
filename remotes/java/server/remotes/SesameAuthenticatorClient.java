@HTTPClient({"path":"/api/v1/authenticator","adapter":"sesame","setup":"SesameSetup"})
interface SesameAuthenticatorClient {
    @PostRequest("/passkey-list")
    Object passkeyList(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/passkey-list-for-principal")
    Object passkeyListForPrincipal(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/passkey-register-begin")
    Object passkeyRegisterBegin(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/passkey-register-finish")
    Object passkeyRegisterFinish(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/passkey-remove")
    Object passkeyRemove(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/passkey-remove-for-principal")
    Object passkeyRemoveForPrincipal(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/recovery-codes-issue")
    Object recoveryCodesIssue(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/set-password")
    Object setPassword(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/set-password-for-principal")
    Object setPasswordForPrincipal(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/totp-activate")
    Object totpActivate(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/totp-enroll")
    Object totpEnroll(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
