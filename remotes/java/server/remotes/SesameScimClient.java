@HTTPClient({"path":"/api/v1/scim","adapter":"sesame","setup":"SesameSetup"})
interface SesameScimClient {
    @PostRequest("/client-disable")
    Object clientDisable(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/client-register")
    Object clientRegister(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/client-rotate-token")
    Object clientRotateToken(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/group-create")
    Object groupCreate(@RequestHeader("Authorization") String authorization, @RequestBody Object body);

    @PostRequest("/group-deprovision")
    Object groupDeprovision(@RequestHeader("Authorization") String authorization, @RequestBody Object body);

    @PostRequest("/group-get")
    Object groupGet(@RequestHeader("Authorization") String authorization, @RequestBody Object body);

    @PostRequest("/group-list")
    Object groupList(@RequestHeader("Authorization") String authorization, @RequestBody Object body);

    @PostRequest("/group-patch")
    Object groupPatch(@RequestHeader("Authorization") String authorization, @RequestBody Object body);

    @PostRequest("/user-create")
    Object userCreate(@RequestHeader("Authorization") String authorization, @RequestBody Object body);

    @PostRequest("/user-deprovision")
    Object userDeprovision(@RequestHeader("Authorization") String authorization, @RequestBody Object body);

    @PostRequest("/user-get")
    Object userGet(@RequestHeader("Authorization") String authorization, @RequestBody Object body);

    @PostRequest("/user-list")
    Object userList(@RequestHeader("Authorization") String authorization, @RequestBody Object body);

    @PostRequest("/user-patch")
    Object userPatch(@RequestHeader("Authorization") String authorization, @RequestBody Object body);
}
