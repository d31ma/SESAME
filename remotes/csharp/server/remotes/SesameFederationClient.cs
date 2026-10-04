[HTTPClient({"path":"/api/v1/federation","adapter":"sesame","setup":"SesameSetup"})]
interface SesameFederationClient {
    [PostRequest("/login-complete")]
    System.Threading.Tasks.Task<BehaviorJSON> LoginComplete([RequestBody] BehaviorJSON body);

    [PostRequest("/login-start")]
    System.Threading.Tasks.Task<BehaviorJSON> LoginStart([RequestBody] BehaviorJSON body);

    [PostRequest("/provider-configure")]
    System.Threading.Tasks.Task<BehaviorJSON> ProviderConfigure([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/provider-disable")]
    System.Threading.Tasks.Task<BehaviorJSON> ProviderDisable([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/provider-get")]
    System.Threading.Tasks.Task<BehaviorJSON> ProviderGet([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/provider-register")]
    System.Threading.Tasks.Task<BehaviorJSON> ProviderRegister([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
