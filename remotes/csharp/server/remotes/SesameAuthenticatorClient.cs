[HTTPClient({"path":"/api/v1/authenticator","adapter":"sesame","setup":"SesameSetup"})]
interface SesameAuthenticatorClient {
    [PostRequest("/passkey-list")]
    System.Threading.Tasks.Task<BehaviorJSON> PasskeyList([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/passkey-list-for-principal")]
    System.Threading.Tasks.Task<BehaviorJSON> PasskeyListForPrincipal([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/passkey-register-begin")]
    System.Threading.Tasks.Task<BehaviorJSON> PasskeyRegisterBegin([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/passkey-register-finish")]
    System.Threading.Tasks.Task<BehaviorJSON> PasskeyRegisterFinish([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/passkey-remove")]
    System.Threading.Tasks.Task<BehaviorJSON> PasskeyRemove([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/passkey-remove-for-principal")]
    System.Threading.Tasks.Task<BehaviorJSON> PasskeyRemoveForPrincipal([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/recovery-codes-issue")]
    System.Threading.Tasks.Task<BehaviorJSON> RecoveryCodesIssue([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/set-password")]
    System.Threading.Tasks.Task<BehaviorJSON> SetPassword([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/set-password-for-principal")]
    System.Threading.Tasks.Task<BehaviorJSON> SetPasswordForPrincipal([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/totp-activate")]
    System.Threading.Tasks.Task<BehaviorJSON> TotpActivate([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/totp-enroll")]
    System.Threading.Tasks.Task<BehaviorJSON> TotpEnroll([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
