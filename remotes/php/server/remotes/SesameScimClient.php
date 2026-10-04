<?php
#[HTTPClient({"path":"/api/v1/scim","adapter":"sesame","setup":"SesameSetup"})]
interface SesameScimClient {
    #[PostRequest("/client-disable")]
    public function clientDisable(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/client-register")]
    public function clientRegister(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/client-rotate-token")]
    public function clientRotateToken(#[RequestHeader("Sesame-Session")] string $session, #[RequestBody] mixed $body): array;

    #[PostRequest("/group-create")]
    public function groupCreate(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;

    #[PostRequest("/group-deprovision")]
    public function groupDeprovision(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;

    #[PostRequest("/group-get")]
    public function groupGet(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;

    #[PostRequest("/group-list")]
    public function groupList(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;

    #[PostRequest("/group-patch")]
    public function groupPatch(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;

    #[PostRequest("/user-create")]
    public function userCreate(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;

    #[PostRequest("/user-deprovision")]
    public function userDeprovision(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;

    #[PostRequest("/user-get")]
    public function userGet(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;

    #[PostRequest("/user-list")]
    public function userList(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;

    #[PostRequest("/user-patch")]
    public function userPatch(#[RequestHeader("Authorization")] string $authorization, #[RequestBody] mixed $body): array;
}
