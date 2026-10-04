@HTTPClient({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})
interface SesameSystemClient {
    @PostRequest("/build")
    fun build(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/metrics")
    fun metrics(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/ping")
    fun ping(@RequestBody body: Any?): Any?

    @PostRequest("/readiness")
    fun readiness(@RequestBody body: Any?): Any?

    @PostRequest("/version")
    fun version(@RequestBody body: Any?): Any?
}
