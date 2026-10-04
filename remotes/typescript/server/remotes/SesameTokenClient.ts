@HTTPClient({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})
export default class SesameTokenClient {
  @PostRequest("/jwks")
  async jwks(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
