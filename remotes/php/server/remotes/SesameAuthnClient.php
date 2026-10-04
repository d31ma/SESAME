<?php
#[HTTPClient({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})]
interface SesameAuthnClient {
    #[PostRequest("/begin")]
    public function begin(#[RequestBody] mixed $body): array;

    #[PostRequest("/complete")]
    public function complete(#[RequestBody] mixed $body): array;

    #[PostRequest("/passkey-options")]
    public function passkeyOptions(#[RequestBody] mixed $body): array;

    #[PostRequest("/verify-passkey")]
    public function verifyPasskey(#[RequestBody] mixed $body): array;

    #[PostRequest("/verify-password")]
    public function verifyPassword(#[RequestBody] mixed $body): array;

    #[PostRequest("/verify-recovery-code")]
    public function verifyRecoveryCode(#[RequestBody] mixed $body): array;

    #[PostRequest("/verify-totp")]
    public function verifyTotp(#[RequestBody] mixed $body): array;
}
