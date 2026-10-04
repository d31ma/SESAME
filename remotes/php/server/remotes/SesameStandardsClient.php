<?php
#[HTTPClient({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})]
interface SesameStandardsClient {
    #[GetRequest("/jwks")]
    public function jwks(): array;

    #[GetRequest("/openid-configuration")]
    public function openidConfiguration(): array;
}
