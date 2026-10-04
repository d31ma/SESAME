from typing import Annotated, Protocol

@http_client({"path":"/api/v1/session","adapter":"sesame","setup":"SesameSetup"})
class SesameSessionClient(Protocol):
    @post_request("/revoke")
    async def revoke(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/revoke-by-id")
    async def revoke_by_id(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/verify")
    async def verify(self, body: Annotated[object, request_body]) -> object: ...
