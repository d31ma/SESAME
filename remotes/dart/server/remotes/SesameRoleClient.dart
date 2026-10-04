@HTTPClient({"path":"/api/v1/role","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameRoleClient {
  @PostRequest("/create")
  Future<Object?> create(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
