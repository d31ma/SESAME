@HTTPClient({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesamePrincipalClient {
  @PostRequest("/create")
  Future<Object?> create(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/get")
  Future<Object?> get(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/suspend")
  Future<Object?> suspend(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
