@HTTPClient({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})
interface SesameGrantClient {
    @PostRequest("/create")
    Object create(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/revoke")
    Object revoke(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
