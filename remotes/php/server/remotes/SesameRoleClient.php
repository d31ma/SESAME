<?php
#[HTTPClient({"path":"/api/v1/role","adapter":"sesame","setup":"SesameSetup"})]
interface SesameRoleClient {
    #[PostRequest("/create")]
    public function create(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
