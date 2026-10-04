@HTTPClient({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameAuthorizeClient {
  @PostRequest("/decide")
  Future<Object?> decide(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/decide-batch")
  Future<Object?> decideBatch(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
