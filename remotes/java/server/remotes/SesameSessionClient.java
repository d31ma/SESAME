@HTTPClient({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})
interface SesameSessionClient {
    @PostRequest("/revoke")
    Object revoke(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/revoke-by-id")
    Object revokeById(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/verify")
    Object verify(@RequestBody Object body);
}
