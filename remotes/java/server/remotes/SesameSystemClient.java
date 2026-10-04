@HTTPClient({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})
interface SesameSystemClient {
    @PostRequest("/build")
    Object build(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/metrics")
    Object metrics(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/ping")
    Object ping(@RequestBody Object body);

    @PostRequest("/readiness")
    Object readiness(@RequestBody Object body);

    @PostRequest("/version")
    Object version(@RequestBody Object body);
}
