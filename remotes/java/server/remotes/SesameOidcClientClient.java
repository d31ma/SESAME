@HTTPClient({"path":"/api/v1/oidc-client","adapter":"sesame","setup":"SesameSetup"})
interface SesameOidcClientClient {
    @PostRequest("/disable")
    Object disable(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/get")
    Object get(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/register")
    Object register(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/rotate-secret")
    Object rotateSecret(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
