@HTTPClient({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})
interface SesameAuthnClient {
    @PostRequest("/begin")
    Object begin(@RequestBody Object body);

    @PostRequest("/complete")
    Object complete(@RequestBody Object body);

    @PostRequest("/passkey-options")
    Object passkeyOptions(@RequestBody Object body);

    @PostRequest("/verify-passkey")
    Object verifyPasskey(@RequestBody Object body);

    @PostRequest("/verify-password")
    Object verifyPassword(@RequestBody Object body);

    @PostRequest("/verify-recovery-code")
    Object verifyRecoveryCode(@RequestBody Object body);

    @PostRequest("/verify-totp")
    Object verifyTotp(@RequestBody Object body);
}
