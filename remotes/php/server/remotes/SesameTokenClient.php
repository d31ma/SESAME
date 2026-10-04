<?php
#[HTTPClient({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})]
interface SesameTokenClient {
    #[PostRequest("/jwks")]
    public function jwks(#[RequestBody] mixed $body): array;
}
