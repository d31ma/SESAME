from typing import Annotated, Protocol

@http_client({"path":"/api/v1/system","adapter":"sesame","setup":"SesameSetup"})
class SesameSystemClient(Protocol):
    @post_request("/build")
    async def build(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/metrics")
    async def metrics(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...

    @post_request("/ping")
    async def ping(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/readiness")
    async def readiness(self, body: Annotated[object, request_body]) -> object: ...

    @post_request("/version")
    async def version(self, body: Annotated[object, request_body]) -> object: ...
