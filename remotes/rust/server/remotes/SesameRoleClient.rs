#[HTTPClient({"path":"/api/v1/role","adapter":"sesame","setup":"SesameSetup"})]
trait SesameRoleClient {
    #[PostRequest("/create")]
    fn create(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
