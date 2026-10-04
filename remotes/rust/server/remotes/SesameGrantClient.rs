#[HTTPClient({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})]
trait SesameGrantClient {
    #[PostRequest("/create")]
    fn create(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/revoke")]
    fn revoke(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
