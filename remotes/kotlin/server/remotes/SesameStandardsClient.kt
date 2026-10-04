@HTTPClient({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})
interface SesameStandardsClient {
    @GetRequest("/jwks")
    fun jwks(): Any?

    @GetRequest("/openid-configuration")
    fun openidConfiguration(): Any?
}
