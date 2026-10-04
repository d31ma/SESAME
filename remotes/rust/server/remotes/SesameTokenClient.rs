#[HTTPClient({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})]
trait SesameTokenClient {
    #[PostRequest("/jwks")]
    fn jwks(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
