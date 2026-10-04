[HTTPClient({"path":"/api/v1/oidc","adapter":"sesame","setup":"SesameSetup"})]
interface SesameOidcClient {
    [PostRequest("/consent-get")]
    System.Threading.Tasks.Task<BehaviorJSON> ConsentGet([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/consent-grant")]
    System.Threading.Tasks.Task<BehaviorJSON> ConsentGrant([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/consent-withdraw")]
    System.Threading.Tasks.Task<BehaviorJSON> ConsentWithdraw([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/device-approve")]
    System.Threading.Tasks.Task<BehaviorJSON> DeviceApprove([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/device-authorize")]
    System.Threading.Tasks.Task<BehaviorJSON> DeviceAuthorize([RequestBody] BehaviorJSON body);

    [PostRequest("/device-deny")]
    System.Threading.Tasks.Task<BehaviorJSON> DeviceDeny([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/device-lookup")]
    System.Threading.Tasks.Task<BehaviorJSON> DeviceLookup([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/dpop-verify")]
    System.Threading.Tasks.Task<BehaviorJSON> DpopVerify([RequestBody] BehaviorJSON body);

    [PostRequest("/interaction-complete")]
    System.Threading.Tasks.Task<BehaviorJSON> InteractionComplete([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/interaction-get")]
    System.Threading.Tasks.Task<BehaviorJSON> InteractionGet([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/pushed-authorize")]
    System.Threading.Tasks.Task<BehaviorJSON> PushedAuthorize([RequestBody] BehaviorJSON body);

    [PostRequest("/refresh-family-get")]
    System.Threading.Tasks.Task<BehaviorJSON> RefreshFamilyGet([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);

    [PostRequest("/refresh-family-revoke")]
    System.Threading.Tasks.Task<BehaviorJSON> RefreshFamilyRevoke([RequestHeader("Sesame-Session")] string session, [RequestBody] BehaviorJSON body);
}
