<?php
#[HTTPClient({"path":"/api/v1/oidc","adapter":"sesame","setup":"SesameSetup"})]
interface SesameOidcClient {
    #[PostRequest("/consent-get")]
    public function consentGet(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/consent-grant")]
    public function consentGrant(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/consent-withdraw")]
    public function consentWithdraw(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/device-approve")]
    public function deviceApprove(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/device-authorize")]
    public function deviceAuthorize(#[RequestBody] mixed $body): array;

    #[PostRequest("/device-deny")]
    public function deviceDeny(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/device-lookup")]
    public function deviceLookup(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/dpop-verify")]
    public function dpopVerify(#[RequestBody] mixed $body): array;

    #[PostRequest("/interaction-complete")]
    public function interactionComplete(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/interaction-get")]
    public function interactionGet(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/pushed-authorize")]
    public function pushedAuthorize(#[RequestBody] mixed $body): array;

    #[PostRequest("/refresh-family-get")]
    public function refreshFamilyGet(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/refresh-family-revoke")]
    public function refreshFamilyRevoke(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
