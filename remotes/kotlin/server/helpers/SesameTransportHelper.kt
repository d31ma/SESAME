@Helper
class SesameTransportHelper : Behaviors.HttpAdapter {
    companion object {
        private const val SNAPSHOT_VARIABLE = "YON_APPLICATION_JSON"
        private const val SECURE_SCHEME = "https"
        private const val PLAIN_SCHEME = "http"
        private val LOOPBACK_HOSTS = listOf("localhost", "127.0.0.1", "[::1]")
        private val ROOT_PATHS = listOf("", "/")
        private val SECURE_PROXY_VARIABLES = listOf("HTTPS_PROXY", "https_proxy")
        private val PLAIN_PROXY_VARIABLES = listOf("HTTP_PROXY", "http_proxy")
        private const val CONTENT_TYPE_HEADER = "Content-Type"
        private const val ACCEPT_HEADER = "Accept"
        private const val JSON_TYPE = "application/json"
        private const val BODY = "body"
        private const val STATUS = "status"
        private const val QUERY_START = "?"
        private const val QUERY_JOINER = "&"
        private const val QUERY_ASSIGNMENT = "="
        private const val SCHEME_SEPARATOR = "://"
        private val REDIRECT_STATUSES = 300..399
        private const val ORIGIN_RULE = "sesame.origin must be an https origin without a path, or http on a loopback address"
        private const val PATH_RULE = "the request path must stay on sesame.origin"
        private const val REDIRECT_RULE = "SESAME answered with a redirect, which this transport never follows"
        private const val SIZE_RULE = "SESAME's answer is larger than the response limit"
        private const val TRANSPORT_RULE = "SESAME could not be reached, or did not answer before the deadline"
    }

    override fun exchange(request: Map<String, Any?>, execution: Behaviors.Execution): Any? {
        val origin = origin()
        val outgoing = outgoing(origin, request)
        return send(origin, outgoing, (request["maxResponseBytes"] as Number).toInt(), execution.deadline)
    }

    private fun origin(): java.net.URI {
        val snapshot = Json.parse(System.getenv(SNAPSHOT_VARIABLE) ?: "{}")
        val configured = member(member(member(snapshot, "yon"), "sesame"), "origin")
        val origin = java.net.URI.create(configured as? String ?: "")
        check(usable(origin)) { ORIGIN_RULE }
        return origin
    }

    private fun member(value: Any?, name: String): Any? = (value as? Map<*, *>)?.get(name)

    private fun usable(origin: java.net.URI): Boolean = listOf(
        allowedScheme(origin),
        origin.host != null,
        origin.rawUserInfo == null,
        (origin.rawPath ?: "") in ROOT_PATHS,
        origin.rawQuery == null,
        origin.rawFragment == null,
    ).all { it }

    private fun allowedScheme(origin: java.net.URI): Boolean {
        val secure = origin.scheme == SECURE_SCHEME
        val local = origin.scheme == PLAIN_SCHEME && origin.host in LOOPBACK_HOSTS
        return secure || local
    }

    private fun outgoing(origin: java.net.URI, request: Map<String, Any?>): java.net.http.HttpRequest {
        val target = java.net.URI.create(origin.scheme + SCHEME_SEPARATOR + origin.rawAuthority + request["path"] + query(members(request, "query")))
        check(origin.rawAuthority == target.rawAuthority) { PATH_RULE }
        val builder = java.net.http.HttpRequest.newBuilder(target)
            .method(request["method"] as String, payload(request))
            .header(CONTENT_TYPE_HEADER, JSON_TYPE)
            .header(ACCEPT_HEADER, JSON_TYPE)
        members(request, "headers").forEach { (name, value) -> builder.setHeader(name.toString(), value.toString()) }
        return builder.build()
    }

    private fun members(request: Map<String, Any?>, name: String): Map<*, *> = request[name] as? Map<*, *> ?: emptyMap<String, Any?>()

    private fun query(values: Map<*, *>): String {
        if (values.isEmpty()) {
            return ""
        }
        return values.entries.joinToString(QUERY_JOINER, QUERY_START) { (name, value) -> encoded(name) + QUERY_ASSIGNMENT + encoded(value) }
    }

    private fun encoded(value: Any?): String = java.net.URLEncoder.encode(value.toString(), Charsets.UTF_8)

    private fun payload(request: Map<String, Any?>): java.net.http.HttpRequest.BodyPublisher {
        if (!request.containsKey(BODY)) {
            return java.net.http.HttpRequest.BodyPublishers.noBody()
        }
        return java.net.http.HttpRequest.BodyPublishers.ofString(Json.stringify(request[BODY]), Charsets.UTF_8)
    }

    private fun send(origin: java.net.URI, outgoing: java.net.http.HttpRequest, limit: Int, deadline: Long): Map<String, Any?> =
        try {
            client(origin).sendAsync(outgoing, java.net.http.HttpResponse.BodyHandlers.ofInputStream())
                .thenApply { response -> answer(response, limit) }
                .get(deadline - System.currentTimeMillis(), java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (failure: java.util.concurrent.ExecutionException) {
            throw IllegalStateException(TRANSPORT_RULE)
        } catch (failure: java.util.concurrent.TimeoutException) {
            throw IllegalStateException(TRANSPORT_RULE)
        }

    private fun client(origin: java.net.URI): java.net.http.HttpClient = java.net.http.HttpClient.newBuilder()
        .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
        .proxy(proxy(origin))
        .build()

    private fun proxy(origin: java.net.URI): java.net.ProxySelector {
        val variables = if (origin.scheme == SECURE_SCHEME) SECURE_PROXY_VARIABLES else PLAIN_PROXY_VARIABLES
        val address = variables.firstNotNullOfOrNull { variable -> System.getenv(variable)?.takeIf { it.isNotEmpty() } }
            ?: return java.net.http.HttpClient.Builder.NO_PROXY
        val proxy = java.net.URI.create(address)
        return java.net.ProxySelector.of(java.net.InetSocketAddress(proxy.host, proxy.port))
    }

    private fun answer(response: java.net.http.HttpResponse<java.io.InputStream>, limit: Int): Map<String, Any?> {
        check(response.statusCode() !in REDIRECT_STATUSES) { REDIRECT_RULE }
        val content = response.body().use { body -> body.readNBytes(limit + 1) }
        check(content.size <= limit) { SIZE_RULE }
        return mapOf(STATUS to response.statusCode(), BODY to jsonOrNothing(String(content, Charsets.UTF_8)))
    }

    private fun jsonOrNothing(content: String): Any? =
        try {
            Json.parse(content)
        } catch (failure: IllegalArgumentException) {
            null
        }
}
