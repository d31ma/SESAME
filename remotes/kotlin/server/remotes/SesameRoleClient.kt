@HTTPClient({"path":"/api/v1/role","adapter":"sesame","setup":"SesameSetup"})
interface SesameRoleClient {
    @PostRequest("/create")
    fun create(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
