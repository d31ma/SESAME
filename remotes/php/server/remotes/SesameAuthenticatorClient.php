<?php
#[HTTPClient({"path":"/api/v1/authenticator","adapter":"sesame","setup":"SesameSetup"})]
interface SesameAuthenticatorClient {
    #[PostRequest("/passkey-list")]
    public function passkeyList(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/passkey-list-for-principal")]
    public function passkeyListForPrincipal(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/passkey-register-begin")]
    public function passkeyRegisterBegin(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/passkey-register-finish")]
    public function passkeyRegisterFinish(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/passkey-remove")]
    public function passkeyRemove(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/passkey-remove-for-principal")]
    public function passkeyRemoveForPrincipal(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/recovery-codes-issue")]
    public function recoveryCodesIssue(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/set-password")]
    public function setPassword(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/set-password-for-principal")]
    public function setPasswordForPrincipal(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/totp-activate")]
    public function totpActivate(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/totp-enroll")]
    public function totpEnroll(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;
}
