<?php
#[HTTPClient({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})]
interface SesameGrantClient {
    #[PostRequest("/create")]
    public function create(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/revoke")]
    public function revoke(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
