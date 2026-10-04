[HTTPClient({"path":"/api/v1/oidc-client","adapter":"sesame","setup":"SesameSetup"})]
interface SesameOidcClientClient {
    [PostRequest("/disable")]
    System.Threading.Tasks.Task<BehaviorJSON> Disable([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/get")]
    System.Threading.Tasks.Task<BehaviorJSON> Get([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/register")]
    System.Threading.Tasks.Task<BehaviorJSON> Register([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/rotate-secret")]
    System.Threading.Tasks.Task<BehaviorJSON> RotateSecret([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
