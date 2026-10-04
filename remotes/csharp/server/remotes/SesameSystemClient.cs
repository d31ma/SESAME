[HTTPClient({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})]
interface SesameSystemClient {
    [PostRequest("/build")]
    System.Threading.Tasks.Task<BehaviorJSON> Build([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/metrics")]
    System.Threading.Tasks.Task<BehaviorJSON> Metrics([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/ping")]
    System.Threading.Tasks.Task<BehaviorJSON> Ping([RequestBody] BehaviorJSON body);

    [PostRequest("/readiness")]
    System.Threading.Tasks.Task<BehaviorJSON> Readiness([RequestBody] BehaviorJSON body);

    [PostRequest("/version")]
    System.Threading.Tasks.Task<BehaviorJSON> Version([RequestBody] BehaviorJSON body);
}
