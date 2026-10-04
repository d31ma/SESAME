@HTTPClient({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})
export default class SesameAuthorizeClient {
  @PostRequest("/decide")
  async decide(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/decide-batch")
  async decideBatch(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
