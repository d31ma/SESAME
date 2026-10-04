[HTTPClient({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})]
interface SesameStandardsClient {
    [GetRequest("/jwks")]
    System.Threading.Tasks.Task<BehaviorJSON> Jwks();

    [GetRequest("/openid-configuration")]
    System.Threading.Tasks.Task<BehaviorJSON> OpenidConfiguration();
}
