#[HTTPClient({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})]
trait SesameGroupClient {
    #[PostRequest("/create")]
    fn create(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/member-add")]
    fn member_add(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/member-remove")]
    fn member_remove(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
