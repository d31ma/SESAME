from typing import Annotated, Protocol

@http_client({"path":"/api/v1/authorize","adapter":"sesame","setup":"SesameSetup"})
class SesameAuthorizeClient(Protocol):
    @post_request("/decide")
    async def decide(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/decide-batch")
    async def decide_batch(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...
