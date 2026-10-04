<?php
#[HTTPClient({"path":"/api/v1/saml","adapter":"sesame","setup":"SesameSetup"})]
interface SesameSamlClient {
    #[PostRequest("/login-complete")]
    public function loginComplete(#[RequestBody] mixed $body): array;

    #[PostRequest("/login-start")]
    public function loginStart(#[RequestBody] mixed $body): array;

    #[PostRequest("/provider-disable")]
    public function providerDisable(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/provider-get")]
    public function providerGet(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/provider-register")]
    public function providerRegister(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
