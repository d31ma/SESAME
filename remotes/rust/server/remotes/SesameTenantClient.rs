#[HTTPClient({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})]
trait SesameTenantClient {
    #[PostRequest("/get")]
    fn get(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
