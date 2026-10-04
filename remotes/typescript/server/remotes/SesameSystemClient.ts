@HTTPClient({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})
export default class SesameSystemClient {
  @PostRequest("/build")
  async build(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/metrics")
  async metrics(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/ping")
  async ping(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/readiness")
  async readiness(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/version")
  async version(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
