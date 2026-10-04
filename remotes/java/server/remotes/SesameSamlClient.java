@HTTPClient({"path":"/api/v1/saml","adapter":"sesame","setup":"SesameSetup"})
interface SesameSamlClient {
    @PostRequest("/login-complete")
    Object loginComplete(@RequestBody Object body);

    @PostRequest("/login-start")
    Object loginStart(@RequestBody Object body);

    @PostRequest("/provider-disable")
    Object providerDisable(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/provider-get")
    Object providerGet(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/provider-register")
    Object providerRegister(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
