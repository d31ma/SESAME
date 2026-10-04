@HTTPClient({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})
interface SesamePrincipalClient {
    @PostRequest("/create")
    Object create(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/get")
    Object get(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/suspend")
    Object suspendPrincipal(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
