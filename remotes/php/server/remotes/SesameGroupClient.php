<?php
#[HTTPClient({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})]
interface SesameGroupClient {
    #[PostRequest("/create")]
    public function create(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/member-add")]
    public function memberAdd(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/member-remove")]
    public function memberRemove(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
