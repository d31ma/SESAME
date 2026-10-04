import asyncio
import json
import os

@Helper
class SesameTransportHelper:
    SNAPSHOT_VARIABLE = 'YON_APPLICATION_JSON'
    SECURE_SCHEME = 'https'
    PLAIN_SCHEME = 'http'
    LOOPBACK_HOSTS = ('localhost', '127.0.0.1', '::1')
    ROOT_PATHS = ('', '/')
    JSON_TYPE = 'application/json'
    TEXT_ENCODING = 'utf-8'
    BODY = 'body'
    LIMIT = 'maxResponseBytes'
    MILLISECONDS_PER_SECOND = 1000
    FIRST_REDIRECT_STATUS = 300
    FIRST_ERROR_STATUS = 400
    ORIGIN_RULE = 'sesame.origin must be an https origin without a path, or http on a loopback address'
    PATH_RULE = 'the request path must stay on sesame.origin'
    REDIRECT_RULE = 'SESAME answered with a redirect, which this transport never follows'
    SIZE_RULE = "SESAME's answer is larger than the response limit"
    DEADLINE_RULE = 'the deadline passed before SESAME answered'

    @staticmethod
    async def exchange(request: dict, execution: object) -> dict:
        origin = SesameTransportHelper.origin()
        outgoing = SesameTransportHelper.outgoing(origin, request)
        return await asyncio.to_thread(SesameTransportHelper.send, outgoing, request)

    @staticmethod
    def origin() -> urllib.parse.SplitResult:
        snapshot = json.loads(os.environ.get(SesameTransportHelper.SNAPSHOT_VARIABLE) or '{}')
        configured = snapshot.get('yon', {}).get('sesame', {}).get('origin', '')
        origin = urllib.parse.urlsplit(configured if isinstance(configured, str) else '')
        if not SesameTransportHelper.usable(origin):
            raise ValueError(SesameTransportHelper.ORIGIN_RULE)
        return origin

    @staticmethod
    def usable(origin: urllib.parse.SplitResult) -> bool:
        checks = [
            SesameTransportHelper.allowed_scheme(origin),
            bool(origin.hostname),
            origin.username is None,
            origin.password is None,
            origin.path in SesameTransportHelper.ROOT_PATHS,
            origin.query == '',
            origin.fragment == '',
        ]
        return all(checks)

    @staticmethod
    def allowed_scheme(origin: urllib.parse.SplitResult) -> bool:
        secure = origin.scheme == SesameTransportHelper.SECURE_SCHEME
        local = origin.scheme == SesameTransportHelper.PLAIN_SCHEME and origin.hostname in SesameTransportHelper.LOOPBACK_HOSTS
        return secure or local

    @staticmethod
    def outgoing(origin: urllib.parse.SplitResult, request: dict) -> urllib.request.Request:
        query = urllib.parse.urlencode({name: SesameTransportHelper.query_text(value) for name, value in request['query'].items()})
        address = urllib.parse.urlunsplit((origin.scheme, origin.netloc, request['path'], query, ''))
        if urllib.parse.urlsplit(address).netloc != origin.netloc:
            raise ValueError(SesameTransportHelper.PATH_RULE)
        headers = {'Content-Type': SesameTransportHelper.JSON_TYPE, 'Accept': SesameTransportHelper.JSON_TYPE}
        headers.update(request['headers'])
        return urllib.request.Request(address, data=SesameTransportHelper.payload(request), headers=headers, method=request['method'])

    @staticmethod
    def query_text(value: object) -> str:
        if isinstance(value, bool):
            return json.dumps(value)
        return str(value)

    @staticmethod
    def payload(request: dict) -> bytes | None:
        if SesameTransportHelper.BODY not in request:
            return None
        return json.dumps(request[SesameTransportHelper.BODY]).encode(SesameTransportHelper.TEXT_ENCODING)

    @staticmethod
    def send(outgoing: urllib.request.Request, request: dict) -> dict:
        with SesameTransportHelper.opener().open(outgoing, timeout=SesameTransportHelper.remaining(request)) as response:
            SesameTransportHelper.require_no_redirect(response.status)
            content = response.read(request[SesameTransportHelper.LIMIT] + 1)
        SesameTransportHelper.require_within(content, request[SesameTransportHelper.LIMIT])
        return {'status': response.status, SesameTransportHelper.BODY: SesameTransportHelper.json_or_nothing(content)}

    @staticmethod
    def opener() -> urllib.request.OpenerDirector:
        opener = urllib.request.OpenerDirector()
        opener.add_handler(urllib.request.ProxyHandler())
        opener.add_handler(urllib.request.HTTPHandler())
        opener.add_handler(urllib.request.HTTPSHandler())
        return opener

    @staticmethod
    def remaining(request: dict) -> float:
        seconds = request['deadline'] / SesameTransportHelper.MILLISECONDS_PER_SECOND - time.time()
        if seconds <= 0:
            raise TimeoutError(SesameTransportHelper.DEADLINE_RULE)
        return seconds

    @staticmethod
    def require_no_redirect(status: int) -> None:
        if SesameTransportHelper.FIRST_REDIRECT_STATUS <= status < SesameTransportHelper.FIRST_ERROR_STATUS:
            raise ValueError(SesameTransportHelper.REDIRECT_RULE)

    @staticmethod
    def require_within(content: bytes, limit: int) -> None:
        if len(content) > limit:
            raise ValueError(SesameTransportHelper.SIZE_RULE)

    @staticmethod
    def json_or_nothing(content: bytes) -> object:
        try:
            return json.loads(content.decode(SesameTransportHelper.TEXT_ENCODING))
        except ValueError:
            return None
