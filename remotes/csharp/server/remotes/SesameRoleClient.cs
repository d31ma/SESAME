[HTTPClient({"path":"/api/v1/role","adapter":"sesame","setup":"SesameSetup"})]
interface SesameRoleClient {
    [PostRequest("/create")]
    System.Threading.Tasks.Task<BehaviorJSON> Create([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
