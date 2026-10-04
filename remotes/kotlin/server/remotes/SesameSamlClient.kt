@HTTPClient({"path":"/api/v1/saml","adapter":"sesame","setup":"SesameSetup"})
interface SesameSamlClient {
    @PostRequest("/login-complete")
    fun loginComplete(@RequestBody body: Any?): Any?

    @PostRequest("/login-start")
    fun loginStart(@RequestBody body: Any?): Any?

    @PostRequest("/provider-disable")
    fun providerDisable(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/provider-get")
    fun providerGet(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/provider-register")
    fun providerRegister(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
