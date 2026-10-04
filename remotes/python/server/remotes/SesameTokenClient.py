from typing import Annotated, Protocol

@http_client({"path":"/api/v1/token","adapter":"sesame","setup":"SesameSetup"})
class SesameTokenClient(Protocol):
    @post_request("/jwks")
    async def jwks(self, body: Annotated[object, request_body]) -> object: ...
