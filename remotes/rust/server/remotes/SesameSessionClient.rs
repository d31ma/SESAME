#[HTTPClient({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})]
trait SesameSessionClient {
    #[PostRequest("/revoke")]
    fn revoke(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/revoke-by-id")]
    fn revoke_by_id(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/verify")]
    fn verify(&self, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
