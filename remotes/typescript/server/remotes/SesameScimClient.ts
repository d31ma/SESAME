@HTTPClient({"path":"/api/v1/scim","adapter":"sesame","setup":"SesameSetup"})
export default class SesameScimClient {
  @PostRequest("/client-disable")
  async clientDisable(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/client-register")
  async clientRegister(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/client-rotate-token")
  async clientRotateToken(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/group-create")
  async groupCreate(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/group-deprovision")
  async groupDeprovision(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/group-get")
  async groupGet(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/group-list")
  async groupList(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/group-patch")
  async groupPatch(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/user-create")
  async userCreate(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/user-deprovision")
  async userDeprovision(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/user-get")
  async userGet(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/user-list")
  async userList(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/user-patch")
  async userPatch(@RequestHeader("Authorization") authorization: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
