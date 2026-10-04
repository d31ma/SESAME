[HTTPClient({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})]
interface SesameAuthorizeClient {
    [PostRequest("/decide")]
    System.Threading.Tasks.Task<BehaviorJSON> Decide([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/decide-batch")]
    System.Threading.Tasks.Task<BehaviorJSON> DecideBatch([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
