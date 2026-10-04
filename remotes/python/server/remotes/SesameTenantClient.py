from typing import Annotated, Protocol

@http_client({"path":"/api/v1/tenant","adapter":"sesame","setup":"SesameSetup"})
class SesameTenantClient(Protocol):
    @post_request("/get")
    async def get(self, session: Annotated[str, request_header("Sesame-Session")], body: Annotated[object, request_body]) -> object: ...
