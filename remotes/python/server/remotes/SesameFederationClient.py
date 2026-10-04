from typing import Annotated, Protocol

@http_client({"path":"/api/v1/federation","adapter":"sesame","setup":"SesameSetup"})
class SesameFederationClient(Protocol):
    @post_request("/login-complete")
    async def login_complete(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/login-start")
    async def login_start(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/provider-configure")
    async def provider_configure(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/provider-disable")
    async def provider_disable(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/provider-get")
    async def provider_get(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/provider-register")
    async def provider_register(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...
