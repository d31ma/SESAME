@HTTPClient({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})
interface SesamePrincipalClient {
    @PostRequest("/create")
    fun create(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/get")
    fun get(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/suspend")
    fun suspendPrincipal(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
