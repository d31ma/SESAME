@HTTPClient({"path":"/api/v1/oidc","adapter":"sesame","setup":"SesameSetup"})
interface SesameOidcClient {
    @PostRequest("/consent-get")
    Object consentGet(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/consent-grant")
    Object consentGrant(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/consent-withdraw")
    Object consentWithdraw(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/device-approve")
    Object deviceApprove(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/device-authorize")
    Object deviceAuthorize(@RequestBody Object body);

    @PostRequest("/device-deny")
    Object deviceDeny(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/device-lookup")
    Object deviceLookup(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/dpop-verify")
    Object dpopVerify(@RequestBody Object body);

    @PostRequest("/interaction-complete")
    Object interactionComplete(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/interaction-get")
    Object interactionGet(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/pushed-authorize")
    Object pushedAuthorize(@RequestBody Object body);

    @PostRequest("/refresh-family-get")
    Object refreshFamilyGet(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);

    @PostRequest("/refresh-family-revoke")
    Object refreshFamilyRevoke(@RequestHeader("Sesame-Session") String session, @RequestBody Object body);
}
