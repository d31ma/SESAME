#[HTTPClient({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})]
trait SesameAuthnClient {
    #[PostRequest("/begin")]
    fn begin(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/complete")]
    fn complete(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/passkey-options")]
    fn passkey_options(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/verify-passkey")]
    fn verify_passkey(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/verify-password")]
    fn verify_password(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/verify-recovery-code")]
    fn verify_recovery_code(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/verify-totp")]
    fn verify_totp(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
