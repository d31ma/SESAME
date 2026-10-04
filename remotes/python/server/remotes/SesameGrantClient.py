from typing import Annotated, Protocol

@http_client({"path":"/api/v1/grant","adapter":"sesame","setup":"SesameSetup"})
class SesameGrantClient(Protocol):
    @post_request("/create")
    async def create(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/revoke")
    async def revoke(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...
