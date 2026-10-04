@HTTPClient({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})
interface SesameAuthorizeClient {
    @PostRequest("/decide")
    Object decide(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/decide-batch")
    Object decideBatch(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
