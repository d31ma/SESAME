from typing import Annotated, Protocol

@http_client({"path":"/oidc","adapter":"sesame","setup":"SesameSetup"})
class SesameStandardsClient(Protocol):
    @get_request("/jwks")
    async def jwks(self) -> object: ...

    @get_request("/openid-configuration")
    async def openid_configuration(self) -> object: ...
