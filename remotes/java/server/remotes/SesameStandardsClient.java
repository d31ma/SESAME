@HTTPClient({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})
interface SesameStandardsClient {
    @GetRequest("/jwks")
    Object jwks();

    @GetRequest("/openid-configuration")
    Object openidConfiguration();
}
