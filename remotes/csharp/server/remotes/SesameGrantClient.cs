[HTTPClient({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})]
interface SesameGrantClient {
    [PostRequest("/create")]
    System.Threading.Tasks.Task<BehaviorJSON> Create([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/revoke")]
    System.Threading.Tasks.Task<BehaviorJSON> Revoke([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
