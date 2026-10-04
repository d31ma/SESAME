#[HTTPClient({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})]
trait SesamePrincipalClient {
    #[PostRequest("/create")]
    fn create(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/get")]
    fn get(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/suspend")]
    fn suspend_principal(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
