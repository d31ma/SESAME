#[HTTPClient({"path":"/api/v1/saml","adapter":"sesame","setup":"SesameSetup"})]
trait SesameSamlClient {
    #[PostRequest("/login-complete")]
    fn login_complete(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/login-start")]
    fn login_start(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/provider-disable")]
    fn provider_disable(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/provider-get")]
    fn provider_get(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/provider-register")]
    fn provider_register(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
