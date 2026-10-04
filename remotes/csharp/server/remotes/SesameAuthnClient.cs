[HTTPClient({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})]
interface SesameAuthnClient {
    [PostRequest("/begin")]
    System.Threading.Tasks.Task<BehaviorJSON> Begin([RequestBody] BehaviorJSON body);

    [PostRequest("/complete")]
    System.Threading.Tasks.Task<BehaviorJSON> Complete([RequestBody] BehaviorJSON body);

    [PostRequest("/passkey-options")]
    System.Threading.Tasks.Task<BehaviorJSON> PasskeyOptions([RequestBody] BehaviorJSON body);

    [PostRequest("/verify-passkey")]
    System.Threading.Tasks.Task<BehaviorJSON> VerifyPasskey([RequestBody] BehaviorJSON body);

    [PostRequest("/verify-password")]
    System.Threading.Tasks.Task<BehaviorJSON> VerifyPassword([RequestBody] BehaviorJSON body);

    [PostRequest("/verify-recovery-code")]
    System.Threading.Tasks.Task<BehaviorJSON> VerifyRecoveryCode([RequestBody] BehaviorJSON body);

    [PostRequest("/verify-totp")]
    System.Threading.Tasks.Task<BehaviorJSON> VerifyTotp([RequestBody] BehaviorJSON body);
}
