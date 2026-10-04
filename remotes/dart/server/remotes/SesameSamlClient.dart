@HTTPClient({"path":"/api/v1/saml","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameSamlClient {
  @PostRequest("/login-complete")
  Future<Object?> loginComplete(@RequestBody Object? body);

  @PostRequest("/login-start")
  Future<Object?> loginStart(@RequestBody Object? body);

  @PostRequest("/provider-disable")
  Future<Object?> providerDisable(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/provider-get")
  Future<Object?> providerGet(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/provider-register")
  Future<Object?> providerRegister(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
