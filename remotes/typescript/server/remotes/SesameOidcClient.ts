@HTTPClient({"path":"/api/v1/oidc","adapter":"sesame","setup":"SesameSetup"})
export default class SesameOidcClient {
  @PostRequest("/consent-get")
  async consentGet(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/consent-grant")
  async consentGrant(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/consent-withdraw")
  async consentWithdraw(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/device-approve")
  async deviceApprove(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/device-authorize")
  async deviceAuthorize(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/device-deny")
  async deviceDeny(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/device-lookup")
  async deviceLookup(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/dpop-verify")
  async dpopVerify(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/interaction-complete")
  async interactionComplete(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/interaction-get")
  async interactionGet(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/pushed-authorize")
  async pushedAuthorize(@RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/refresh-family-get")
  async refreshFamilyGet(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}

  @PostRequest("/refresh-family-revoke")
  async refreshFamilyRevoke(@RequestHeader("Sesame-Session") session: string, @RequestBody body: BehaviorJsonValue): Promise<BehaviorJsonValue | void> {}
}
