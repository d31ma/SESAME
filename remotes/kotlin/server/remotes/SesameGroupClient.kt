@HTTPClient({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})
interface SesameGroupClient {
    @PostRequest("/create")
    fun create(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/member-add")
    fun memberAdd(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/member-remove")
    fun memberRemove(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
