@HTTPClient({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameGroupClient {
  @PostRequest("/create")
  Future<Object?> create(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/member-add")
  Future<Object?> memberAdd(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/member-remove")
  Future<Object?> memberRemove(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);
}
