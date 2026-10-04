@HTTPClient({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})
interface SesameTenantClient {
    @PostRequest("/get")
    Object get(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
