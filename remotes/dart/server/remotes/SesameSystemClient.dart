@HTTPClient({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameSystemClient {
  @PostRequest("/build")
  Future<Object?> build(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/metrics")
  Future<Object?> metrics(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/ping")
  Future<Object?> ping(@RequestBody Object? body);

  @PostRequest("/readiness")
  Future<Object?> readiness(@RequestBody Object? body);

  @PostRequest("/version")
  Future<Object?> version(@RequestBody Object? body);
}
