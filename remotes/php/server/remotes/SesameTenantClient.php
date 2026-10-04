<?php
#[HTTPClient({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})]
interface SesameTenantClient {
    #[PostRequest("/get")]
    public function get(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
