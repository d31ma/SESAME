<?php
#[HTTPClient({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})]
interface SesameSessionClient {
    #[PostRequest("/revoke")]
    public function revoke(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/revoke-by-id")]
    public function revokeById(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/verify")]
    public function verify(#[RequestBody] mixed $body): array;
}
