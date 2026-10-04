#[HTTPClient({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})]
trait SesameAuthorizeClient {
    #[PostRequest("/decide")]
    fn decide(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/decide-batch")]
    fn decide_batch(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
