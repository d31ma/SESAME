@HTTPClient({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})
interface SesameSessionClient {
    @PostRequest("/revoke")
    fun revoke(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/revoke-by-id")
    fun revokeById(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/verify")
    fun verify(@RequestBody body: Any?): Any?
}
