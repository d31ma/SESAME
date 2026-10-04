@HTTPClient({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameTenantClient {
  @PostRequest("/get")
  Future<Object?> get(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
