@HTTPClient({"path":"/api/v1/role","adapter":"sesame","setup":"SesameSetup"})
interface SesameRoleClient {
    @PostRequest("/create")
    Object create(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
