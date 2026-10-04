@HTTPClient({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})
interface SesameAuthorizeClient {
    @PostRequest("/decide")
    fun decide(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/decide-batch")
    fun decideBatch(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
