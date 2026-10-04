@HTTPClient({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})
export default class SesamePrincipalClient {
  @PostRequest("/create")
  async create(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/get")
  async get(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/suspend")
  async suspend(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
