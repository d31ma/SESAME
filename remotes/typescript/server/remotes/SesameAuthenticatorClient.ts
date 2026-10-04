@HTTPClient({"path":"/api/v1/authenticator","adapter":"sesame","setup":"SesameSetup"})
export default class SesameAuthenticatorClient {
  @PostRequest("/passkey-list")
  async passkeyList(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/passkey-list-for-principal")
  async passkeyListForPrincipal(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/passkey-register-begin")
  async passkeyRegisterBegin(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/passkey-register-finish")
  async passkeyRegisterFinish(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/passkey-remove")
  async passkeyRemove(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/passkey-remove-for-principal")
  async passkeyRemoveForPrincipal(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/recovery-codes-issue")
  async recoveryCodesIssue(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/set-password")
  async setPassword(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/set-password-for-principal")
  async setPasswordForPrincipal(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/totp-activate")
  async totpActivate(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/totp-enroll")
  async totpEnroll(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
