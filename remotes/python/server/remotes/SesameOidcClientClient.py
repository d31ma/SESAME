from typing import Annotated, Protocol

@http_client({"path":"/api/v1/oidc-client","adapter":"sesame","setup":"SesameSetup"})
class SesameOidcClientClient(Protocol):
    @post_request("/disable")
    async def disable(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/get")
    async def get(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/register")
    async def register(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/rotate-secret")
    async def rotate_secret(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...
