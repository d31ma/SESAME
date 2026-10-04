@HTTPClient({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})
export default class SesameTenantClient {
  @PostRequest("/get")
  async get(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
