[HTTPClient({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})]
interface SesameTenantClient {
    [PostRequest("/get")]
    System.Threading.Tasks.Task<BehaviorJSON> Get([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
