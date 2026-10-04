@HTTPClient({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})
interface SesameTokenClient {
    @PostRequest("/jwks")
    Object jwks(@RequestBody Object body);
}
