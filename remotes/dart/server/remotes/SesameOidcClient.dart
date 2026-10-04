@HTTPClient({"path":"/api/v1/oidc","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameOidcClient {
  @PostRequest("/consent-get")
  Future<Object?> consentGet(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/consent-grant")
  Future<Object?> consentGrant(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/consent-withdraw")
  Future<Object?> consentWithdraw(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/device-approve")
  Future<Object?> deviceApprove(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/device-authorize")
  Future<Object?> deviceAuthorize(@RequestBody Object? body);

  @PostRequest("/device-deny")
  Future<Object?> deviceDeny(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/device-lookup")
  Future<Object?> deviceLookup(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/dpop-verify")
  Future<Object?> dpopVerify(@RequestBody Object? body);

  @PostRequest("/interaction-complete")
  Future<Object?> interactionComplete(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/interaction-get")
  Future<Object?> interactionGet(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/pushed-authorize")
  Future<Object?> pushedAuthorize(@RequestBody Object? body);

  @PostRequest("/refresh-family-get")
  Future<Object?> refreshFamilyGet(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/refresh-family-revoke")
  Future<Object?> refreshFamilyRevoke(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
