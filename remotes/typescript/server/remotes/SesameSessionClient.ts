@HTTPClient({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})
export default class SesameSessionClient {
  @PostRequest("/revoke")
  async revoke(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/revoke-by-id")
  async revokeById(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/verify")
  async verify(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
