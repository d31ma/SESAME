from typing import Annotated, Protocol

@http_client({"path":"/api/v1/principal","adapter":"sesame","setup":"SesameSetup"})
class SesamePrincipalClient(Protocol):
    @post_request("/create")
    async def create(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/get")
    async def get(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/suspend")
    async def suspend(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...
