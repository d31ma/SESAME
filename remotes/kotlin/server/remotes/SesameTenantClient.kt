@HTTPClient({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})
interface SesameTenantClient {
    @PostRequest("/get")
    fun get(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
