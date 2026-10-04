@Helper
final class SesameTransportHelper implements Behaviors.HttpAdapter {
    private static final String SNAPSHOT_VARIABLE = "YON_APPLICATION_JSON";
    private static final String SECURE_SCHEME = "https";
    private static final String PLAIN_SCHEME = "http";
    private static final java.util.List<String> LOOPBACK_HOSTS = java.util.List.of("localhost", "127.0.0.1", "[::1]");
    private static final java.util.List<String> ROOT_PATHS = java.util.List.of("", "/");
    private static final java.util.List<String> SECURE_PROXY_VARIABLES = java.util.List.of("HTTPS_PROXY", "https_proxy");
    private static final java.util.List<String> PLAIN_PROXY_VARIABLES = java.util.List.of("HTTP_PROXY", "http_proxy");
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String JSON_TYPE = "application/json";
    private static final String BODY = "body";
    private static final String STATUS = "status";
    private static final String QUERY_START = "?";
    private static final String QUERY_JOINER = "&";
    private static final String QUERY_ASSIGNMENT = "=";
    private static final String SCHEME_SEPARATOR = "://";
    private static final int FIRST_REDIRECT_STATUS = 300;
    private static final int FIRST_ERROR_STATUS = 400;
    private static final String ORIGIN_RULE = "sesame.origin must be an https origin without a path, or http on a loopback address";
    private static final String PATH_RULE = "the request path must stay on sesame.origin";
    private static final String REDIRECT_RULE = "SESAME answered with a redirect, which this transport never follows";
    private static final String SIZE_RULE = "SESAME's answer is larger than the response limit";
    private static final String TRANSPORT_RULE = "SESAME could not be reached, or did not answer before the deadline";

    @Override
    public Object exchange(java.util.Map<String, Object> request, Behaviors.Execution execution) {
        java.net.URI origin = origin();
        java.net.http.HttpRequest outgoing = outgoing(origin, request);
        return send(origin, outgoing, ((Number) request.get("maxResponseBytes")).intValue(), execution.deadline);
    }

    private java.net.URI origin() {
        Object snapshot = Json.parse(java.util.Objects.requireNonNullElse(System.getenv(SNAPSHOT_VARIABLE), "{}"));
        Object configured = member(member(member(snapshot, "yon"), "sesame"), "origin");
        java.net.URI origin = java.net.URI.create(configured instanceof String text ? text : "");
        if (!usable(origin)) {
            throw new IllegalStateException(ORIGIN_RULE);
        }
        return origin;
    }

    private Object member(Object value, String name) {
        return value instanceof java.util.Map<?, ?> map ? map.get(name) : null;
    }

    private boolean usable(java.net.URI origin) {
        java.util.List<Boolean> checks = java.util.List.of(
            allowedScheme(origin),
            origin.getHost() != null,
            origin.getRawUserInfo() == null,
            ROOT_PATHS.contains(java.util.Objects.requireNonNullElse(origin.getRawPath(), "")),
            origin.getRawQuery() == null,
            origin.getRawFragment() == null);
        return !checks.contains(false);
    }

    private boolean allowedScheme(java.net.URI origin) {
        boolean secure = SECURE_SCHEME.equals(origin.getScheme());
        boolean local = PLAIN_SCHEME.equals(origin.getScheme()) && LOOPBACK_HOSTS.contains(origin.getHost());
        return secure || local;
    }

    private java.net.http.HttpRequest outgoing(java.net.URI origin, java.util.Map<String, Object> request) {
        java.net.URI target = java.net.URI.create(origin.getScheme() + SCHEME_SEPARATOR + origin.getRawAuthority()
            + request.get("path") + query(members(request, "query")));
        if (!origin.getRawAuthority().equals(target.getRawAuthority())) {
            throw new IllegalStateException(PATH_RULE);
        }
        java.net.http.HttpRequest.Builder builder = java.net.http.HttpRequest.newBuilder(target)
            .method((String) request.get("method"), payload(request))
            .header(CONTENT_TYPE_HEADER, JSON_TYPE)
            .header(ACCEPT_HEADER, JSON_TYPE);
        members(request, "headers").forEach((name, value) -> builder.setHeader(String.valueOf(name), String.valueOf(value)));
        return builder.build();
    }

    private java.util.Map<?, ?> members(java.util.Map<String, Object> request, String name) {
        return request.get(name) instanceof java.util.Map<?, ?> map ? map : java.util.Map.of();
    }

    private String query(java.util.Map<?, ?> values) {
        java.util.StringJoiner joiner = new java.util.StringJoiner(QUERY_JOINER, QUERY_START, "").setEmptyValue("");
        values.forEach((name, value) -> joiner.add(encoded(name) + QUERY_ASSIGNMENT + encoded(value)));
        return joiner.toString();
    }

    private String encoded(Object value) {
        return java.net.URLEncoder.encode(String.valueOf(value), java.nio.charset.StandardCharsets.UTF_8);
    }

    private java.net.http.HttpRequest.BodyPublisher payload(java.util.Map<String, Object> request) {
        if (!request.containsKey(BODY)) {
            return java.net.http.HttpRequest.BodyPublishers.noBody();
        }
        return java.net.http.HttpRequest.BodyPublishers.ofString(Json.stringify(request.get(BODY)), java.nio.charset.StandardCharsets.UTF_8);
    }

    private java.util.Map<String, Object> send(java.net.URI origin, java.net.http.HttpRequest outgoing, int limit, long deadline) {
        try {
            return client(origin).sendAsync(outgoing, java.net.http.HttpResponse.BodyHandlers.ofInputStream())
                .thenApply(response -> answer(response, limit))
                .get(deadline - System.currentTimeMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException failure) {
            throw new IllegalStateException(TRANSPORT_RULE);
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(TRANSPORT_RULE);
        }
    }

    private java.net.http.HttpClient client(java.net.URI origin) {
        return java.net.http.HttpClient.newBuilder()
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
            .proxy(proxy(origin))
            .build();
    }

    private java.net.ProxySelector proxy(java.net.URI origin) {
        java.util.List<String> variables = SECURE_SCHEME.equals(origin.getScheme()) ? SECURE_PROXY_VARIABLES : PLAIN_PROXY_VARIABLES;
        for (String variable : variables) {
            String address = System.getenv(variable);
            if (address != null && !address.isEmpty()) {
                java.net.URI proxy = java.net.URI.create(address);
                return java.net.ProxySelector.of(new java.net.InetSocketAddress(proxy.getHost(), proxy.getPort()));
            }
        }
        return java.net.http.HttpClient.Builder.NO_PROXY;
    }

    private java.util.Map<String, Object> answer(java.net.http.HttpResponse<java.io.InputStream> response, int limit) {
        if (response.statusCode() >= FIRST_REDIRECT_STATUS && response.statusCode() < FIRST_ERROR_STATUS) {
            throw new IllegalStateException(REDIRECT_RULE);
        }
        byte[] content = bounded(response.body(), limit);
        java.util.Map<String, Object> answer = new java.util.LinkedHashMap<>();
        answer.put(STATUS, response.statusCode());
        answer.put(BODY, jsonOrNothing(new String(content, java.nio.charset.StandardCharsets.UTF_8)));
        return answer;
    }

    private byte[] bounded(java.io.InputStream body, int limit) {
        try (body) {
            byte[] content = body.readNBytes(limit + 1);
            if (content.length > limit) {
                throw new IllegalStateException(SIZE_RULE);
            }
            return content;
        } catch (java.io.IOException failure) {
            throw new java.io.UncheckedIOException(failure);
        }
    }

    private Object jsonOrNothing(String content) {
        try {
            return Json.parse(content);
        } catch (IllegalArgumentException failure) {
            return null;
        }
    }
}
