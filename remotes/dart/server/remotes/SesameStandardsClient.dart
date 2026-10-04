@HTTPClient({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameStandardsClient {
  @GetRequest("/jwks")
  Future<Object?> jwks();

  @GetRequest("/openid-configuration")
  Future<Object?> openidConfiguration();
}
