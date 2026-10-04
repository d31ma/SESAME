@HTTPClient({"path":"/api/v1/oidc-client","adapter":"sesame","setup":"SesameSetup"})
interface SesameOidcClientClient {
    @PostRequest("/disable")
    fun disable(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/get")
    fun get(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/register")
    fun register(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/rotate-secret")
    fun rotateSecret(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
