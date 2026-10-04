@HTTPClient({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameTokenClient {
  @PostRequest("/jwks")
  Future<Object?> jwks(@RequestBody Object? body);
}
