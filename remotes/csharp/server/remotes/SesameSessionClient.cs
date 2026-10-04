[HTTPClient({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})]
interface SesameSessionClient {
    [PostRequest("/revoke")]
    System.Threading.Tasks.Task<BehaviorJSON> Revoke([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/revoke-by-id")]
    System.Threading.Tasks.Task<BehaviorJSON> RevokeById([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/verify")]
    System.Threading.Tasks.Task<BehaviorJSON> Verify([RequestBody] BehaviorJSON body);
}
