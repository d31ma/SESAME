@HTTPClient({"path":"/api/v1/oidc-client","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameOidcClientClient {
  @PostRequest("/disable")
  Future<Object?> disable(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/get")
  Future<Object?> get(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/register")
  Future<Object?> register(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/rotate-secret")
  Future<Object?> rotateSecret(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
