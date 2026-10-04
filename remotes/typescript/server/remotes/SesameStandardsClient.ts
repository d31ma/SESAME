@HTTPClient({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})
export default class SesameStandardsClient {
  @GetRequest("/jwks")
  async jwks(): Promise<BehaviorJsonValue | void> {}

  @GetRequest("/openid-configuration")
  async openidConfiguration(): Promise<BehaviorJsonValue | void> {}
}
