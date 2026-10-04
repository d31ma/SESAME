#[HTTPClient({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})]
trait SesameSystemClient {
    #[PostRequest("/build")]
    fn build(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/metrics")]
    fn metrics(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/ping")]
    fn ping(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/readiness")]
    fn readiness(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/version")]
    fn version(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
