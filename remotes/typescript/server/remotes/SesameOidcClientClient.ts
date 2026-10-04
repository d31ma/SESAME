@HTTPClient({"path":"/api/v1/oidc-client","adapter":"sesame","setup":"SesameSetup"})
export default class SesameOidcClientClient {
  @PostRequest("/disable")
  async disable(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/get")
  async get(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/register")
  async register(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/rotate-secret")
  async rotateSecret(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
