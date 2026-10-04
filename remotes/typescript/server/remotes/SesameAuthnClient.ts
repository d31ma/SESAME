@HTTPClient({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})
export default class SesameAuthnClient {
  @PostRequest("/begin")
  async begin(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/complete")
  async complete(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/passkey-options")
  async passkeyOptions(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/verify-passkey")
  async verifyPasskey(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/verify-password")
  async verifyPassword(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/verify-recovery-code")
  async verifyRecoveryCode(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/verify-totp")
  async verifyTotp(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
