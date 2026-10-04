@HTTPClient({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameSessionClient {
  @PostRequest("/revoke")
  Future<Object?> revoke(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/revoke-by-id")
  Future<Object?> revokeById(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/verify")
  Future<Object?> verify(@RequestBody Object? body);
}
