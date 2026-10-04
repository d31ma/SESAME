<?php
#[HTTPClient({"path":"/api/v1/oidc-client","adapter":"sesame","setup":"SesameSetup"})]
interface SesameOidcClientClient {
    #[PostRequest("/disable")]
    public function disable(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/get")]
    public function get(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/register")]
    public function register(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/rotate-secret")]
    public function rotateSecret(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
