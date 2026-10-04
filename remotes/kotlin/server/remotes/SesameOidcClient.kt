@HTTPClient({"path":"/api/v1/oidc","adapter":"sesame","setup":"SesameSetup"})
interface SesameOidcClient {
    @PostRequest("/consent-get")
    fun consentGet(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/consent-grant")
    fun consentGrant(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/consent-withdraw")
    fun consentWithdraw(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/device-approve")
    fun deviceApprove(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/device-authorize")
    fun deviceAuthorize(@RequestBody body: Any?): Any?

    @PostRequest("/device-deny")
    fun deviceDeny(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/device-lookup")
    fun deviceLookup(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/dpop-verify")
    fun dpopVerify(@RequestBody body: Any?): Any?

    @PostRequest("/interaction-complete")
    fun interactionComplete(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/interaction-get")
    fun interactionGet(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/pushed-authorize")
    fun pushedAuthorize(@RequestBody body: Any?): Any?

    @PostRequest("/refresh-family-get")
    fun refreshFamilyGet(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?

    @PostRequest("/refresh-family-revoke")
    fun refreshFamilyRevoke(@RequestHeader("Sesame-Session") session: String, @RequestBody body: Any?): Any?
}
