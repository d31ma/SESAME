from typing import Annotated, Protocol

@http_client({"path":"/api/v1/group","adapter":"sesame","setup":"SesameSetup"})
class SesameGroupClient(Protocol):
    @post_request("/create")
    async def create(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/member-add")
    async def member_add(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/member-remove")
    async def member_remove(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...
