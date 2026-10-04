[HTTPClient({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})]
interface SesameTokenClient {
    [PostRequest("/jwks")]
    System.Threading.Tasks.Task<BehaviorJSON> Jwks([RequestBody] BehaviorJSON body);
}
