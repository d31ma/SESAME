from typing import Annotated, Protocol

@http_client({"path":"/api/v1/authn","adapter":"sesame","setup":"SesameSetup"})
class SesameAuthnClient(Protocol):
    @post_request("/begin")
    async def begin(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/complete")
    async def complete(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/passkey-options")
    async def passkey_options(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/verify-passkey")
    async def verify_passkey(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/verify-password")
    async def verify_password(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/verify-recovery-code")
    async def verify_recovery_code(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/verify-totp")
    async def verify_totp(self, body: Annotated[object, request_body]) -> object: ...
