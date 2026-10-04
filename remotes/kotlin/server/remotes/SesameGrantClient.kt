@HTTPClient({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})
interface SesameGrantClient {
    @PostRequest("/create")
    fun create(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/revoke")
    fun revoke(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
