#[HTTPClient({"path":"/api/v1/authenticator","adapter":"sesame","setup":"SesameSetup"})]
trait SesameAuthenticatorClient {
    #[PostRequest("/passkey-list")]
    fn passkey_list(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/passkey-list-for-principal")]
    fn passkey_list_for_principal(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/passkey-register-begin")]
    fn passkey_register_begin(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/passkey-register-finish")]
    fn passkey_register_finish(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/passkey-remove")]
    fn passkey_remove(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/passkey-remove-for-principal")]
    fn passkey_remove_for_principal(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/recovery-codes-issue")]
    fn recovery_codes_issue(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/set-password")]
    fn set_password(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/set-password-for-principal")]
    fn set_password_for_principal(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/totp-activate")]
    fn totp_activate(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/totp-enroll")]
    fn totp_enroll(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
