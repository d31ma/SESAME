[HTTPClient({"path":"/api/v1/scim","adapter":"sesame","setup":"SesameSetup"})]
interface SesameScimClient {
    [PostRequest("/client-disable")]
    System.Threading.Tasks.Task<BehaviorJSON> ClientDisable([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/client-register")]
    System.Threading.Tasks.Task<BehaviorJSON> ClientRegister([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/client-rotate-token")]
    System.Threading.Tasks.Task<BehaviorJSON> ClientRotateToken([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/group-create")]
    System.Threading.Tasks.Task<BehaviorJSON> GroupCreate([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);

    [PostRequest("/group-deprovision")]
    System.Threading.Tasks.Task<BehaviorJSON> GroupDeprovision([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);

    [PostRequest("/group-get")]
    System.Threading.Tasks.Task<BehaviorJSON> GroupGet([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);

    [PostRequest("/group-list")]
    System.Threading.Tasks.Task<BehaviorJSON> GroupList([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);

    [PostRequest("/group-patch")]
    System.Threading.Tasks.Task<BehaviorJSON> GroupPatch([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);

    [PostRequest("/user-create")]
    System.Threading.Tasks.Task<BehaviorJSON> UserCreate([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);

    [PostRequest("/user-deprovision")]
    System.Threading.Tasks.Task<BehaviorJSON> UserDeprovision([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);

    [PostRequest("/user-get")]
    System.Threading.Tasks.Task<BehaviorJSON> UserGet([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);

    [PostRequest("/user-list")]
    System.Threading.Tasks.Task<BehaviorJSON> UserList([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);

    [PostRequest("/user-patch")]
    System.Threading.Tasks.Task<BehaviorJSON> UserPatch([RequestHeader("Authorization")] string authorization, [RequestBody] BehaviorJSON body);
}
