@HTTPClient({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})
interface SesameTokenClient {
    @PostRequest("/jwks")
    fun jwks(@RequestBody body: Any?): Any?
}
