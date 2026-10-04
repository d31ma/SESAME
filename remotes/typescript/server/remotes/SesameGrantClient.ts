@HTTPClient({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})
export default class SesameGrantClient {
  @PostRequest("/create")
  async create(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/revoke")
  async revoke(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
