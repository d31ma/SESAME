<?php
#[HTTPClient({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})]
interface SesameAuthorizeClient {
    #[PostRequest("/decide")]
    public function decide(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/decide-batch")]
    public function decideBatch(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
