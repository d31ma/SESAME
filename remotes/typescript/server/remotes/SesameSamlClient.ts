@HTTPClient({"path":"/api/v1/saml","adapter":"sesame","setup":"SesameSetup"})
export default class SesameSamlClient {
  @PostRequest("/login-complete")
  async loginComplete(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/login-start")
  async loginStart(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/provider-disable")
  async providerDisable(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/provider-get")
  async providerGet(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/provider-register")
  async providerRegister(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
