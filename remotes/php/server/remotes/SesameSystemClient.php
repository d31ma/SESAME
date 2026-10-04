<?php
#[HTTPClient({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})]
interface SesameSystemClient {
    #[PostRequest("/build")]
    public function build(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/metrics")]
    public function metrics(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/ping")]
    public function ping(#[RequestBody] mixed $body): array;

    #[PostRequest("/readiness")]
    public function readiness(#[RequestBody] mixed $body): array;

    #[PostRequest("/version")]
    public function version(#[RequestBody] mixed $body): array;
}
