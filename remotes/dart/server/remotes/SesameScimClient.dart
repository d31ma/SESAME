@HTTPClient({"path":"/api/v1/scim","adapter":"sesame","setup":"SesameSetup"})
abstract interface class SesameScimClient {
  @PostRequest("/client-disable")
  Future<Object?> clientDisable(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/client-register")
  Future<Object?> clientRegister(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/client-rotate-token")
  Future<Object?> clientRotateToken(@RequestHeader("Sesame-Session") String session, @RequestBody Object? body);

  @PostRequest("/group-create")
  Future<Object?> groupCreate(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);

  @PostRequest("/group-deprovision")
  Future<Object?> groupDeprovision(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);

  @PostRequest("/group-get")
  Future<Object?> groupGet(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);

  @PostRequest("/group-list")
  Future<Object?> groupList(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);

  @PostRequest("/group-patch")
  Future<Object?> groupPatch(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);

  @PostRequest("/user-create")
  Future<Object?> userCreate(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);

  @PostRequest("/user-deprovision")
  Future<Object?> userDeprovision(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);

  @PostRequest("/user-get")
  Future<Object?> userGet(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);

  @PostRequest("/user-list")
  Future<Object?> userList(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);

  @PostRequest("/user-patch")
  Future<Object?> userPatch(@RequestHeader("Authorization") String authorization, @RequestBody Object? body);
}
