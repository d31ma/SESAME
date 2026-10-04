@HTTPClient({"path":"/api/v1/role","adapter":"sesame","setup":"SesameSetup"})
export default class SesameRoleClient {
  @PostRequest("/create")
  async create(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
