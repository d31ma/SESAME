@HTTPClient({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameGrantClient {
  @PostRequest("/create")
  Future<Object?> create(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/revoke")
  Future<Object?> revoke(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
