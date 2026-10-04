<?php
#[HTTPClient({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})]
interface SesamePrincipalClient {
    #[PostRequest("/create")]
    public function create(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/get")]
    public function get(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/suspend")]
    public function suspend(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
