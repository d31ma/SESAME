#[HTTPClient({"path":"/api/v1/scim","adapter":"sesame","setup":"SesameSetup"})]
trait SesameScimClient {
    #[PostRequest("/client-disable")]
    fn client_disable(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/client-register")]
    fn client_register(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/client-rotate-token")]
    fn client_rotate_token(&self, #[RequestHeader("Sesame-Session")] session: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/group-create")]
    fn group_create(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/group-deprovision")]
    fn group_deprovision(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/group-get")]
    fn group_get(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/group-list")]
    fn group_list(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/group-patch")]
    fn group_patch(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/user-create")]
    fn user_create(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/user-deprovision")]
    fn user_deprovision(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/user-get")]
    fn user_get(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/user-list")]
    fn user_list(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;

    #[PostRequest("/user-patch")]
    fn user_patch(&self, #[RequestHeader("Authorization")] authorization: BehaviorValue, #[RequestBody] body: BehaviorValue) -> BehaviorResult<BehaviorValue>;
}
