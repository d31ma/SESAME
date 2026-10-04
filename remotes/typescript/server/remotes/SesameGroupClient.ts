@HTTPClient({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})
export default class SesameGroupClient {
  @PostRequest("/create")
  async create(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/member-add")
  async memberAdd(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/member-remove")
  async memberRemove(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
