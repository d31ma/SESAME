[HTTPClient({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})]
interface SesamePrincipalClient {
    [PostRequest("/create")]
    System.Threading.Tasks.Task<BehaviorJSON> Create([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/get")]
    System.Threading.Tasks.Task<BehaviorJSON> Get([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/suspend")]
    System.Threading.Tasks.Task<BehaviorJSON> Suspend([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
