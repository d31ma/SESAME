// Runs the shared SDK contract scenario against real compiled binaries.
//
// Every SESAME SDK drives this same sequence, so a divergence in any one
// client fails its own suite rather than hiding behind a mock. The harness is
// plain JDK: adding JUnit would contradict the shim's dependency-free promise.

package ma.del.sesame;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class SesameContractTest {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Path root = repositoryRoot();
        Path workspace = Files.createTempDirectory("sesame-java-contract-");
        try {
            Path sesameBinary = build(root, workspace, "sesame", "./cmd/sesame");
            Path fakeFYLO = build(root, workspace, "fake-fylo",
                    "./internal/adapters/fylo/testdata/fakefylo");
            Path deployment = initializeDeployment(
                    root, workspace, sesameBinary, fakeFYLO);

            Sesame.Options options = new Sesame.Options();
            options.binary = sesameBinary.toString();
            options.deployment = deployment.toString();

            try (Sesame client = new Sesame(options)) {
                run(client);
            }
            System.out.println("ok\tjava contract scenario\t" + checks + " checks");
        } finally {
            deleteTree(workspace);
        }
    }

    private static void run(Sesame client) {
        // System operations report a storage-backed process.
        equals("ok", field(client.ping(), "status"), "ping status");
        equals("ok", field(client.readiness(), "status"), "readiness status");
        equals("sesame", field(client.version(), "name"), "version name");
        equals(Boolean.TRUE, field(client.metrics(), "storage_configured"), "storage configured");

        // Tenant and principal.
        Object tenant = client.tenantBootstrap("acme");
        String tenantId = (String) field(field(tenant, "tenant"), "tenant_id");
        Object principal = client.principalCreate(tenantId, "human", "email", "Alice@Example.com");
        String principalId = (String) field(principal, "principal_id");
        equals("alice@example.com", field(field(principal, "identifier"), "value"),
                "the engine normalizes the identifier");

        // A duplicate claim returns the stable conflict code.
        equals("identifier_conflict",
                codeOf(() -> client.principalCreate(tenantId, "workload", "email", "alice@example.com")),
                "duplicate identifier");

        // Authorization: deny by default, allow after a grant, deny after revoke.
        Map<String, Object> permission = new LinkedHashMap<>();
        permission.put("action", "doc:read");
        permission.put("resource", "project:*");
        List<Map<String, Object>> permissions = new ArrayList<>();
        permissions.add(permission);
        String roleId = (String) field(client.roleCreate(tenantId, "reader", permissions), "role_id");

        Object denied = client.decide(tenantId, principalId, "doc:read", "project:alpha");
        equals("deny", field(denied, "decision"), "pre-grant decision");
        equals("deny_no_grant", field(denied, "reason_code"), "pre-grant reason");

        String grantId = (String) field(client.grantCreate(tenantId, principalId, roleId), "grant_id");
        Object allowed = client.decide(tenantId, principalId, "doc:read", "project:alpha");
        equals("allow", field(allowed, "decision"), "post-grant decision");
        equals("allow_role_grant", field(allowed, "reason_code"), "post-grant reason");

        client.grantRevoke(grantId);
        equals("deny", field(client.decide(tenantId, principalId, "doc:read", "project:alpha"),
                "decision"), "post-revoke decision");

        // Authentication: password login, session verification, revocation.
        String password = "correct horse battery staple";
        client.setPassword(principalId, password);
        Object begun = client.authnBegin(tenantId, "email", "Alice@Example.com");
        equals("awaiting_factor", field(begun, "state"), "begin state");
        String transactionId = (String) field(begun, "transaction_id");

        Object wrong = client.authnVerifyPassword(transactionId, "wrong password value");
        equals(4L, field(wrong, "attempts_left"), "attempts after a wrong password");

        Object verified = client.authnVerifyPassword(transactionId, password);
        equals("password", field(verified, "assurance"), "assurance");

        Object issued = client.authnComplete(transactionId, 3600);
        String sessionId = (String) field(issued, "session_id");
        String secret = (String) field(issued, "session_secret");

        Object session = client.sessionVerify(sessionId, secret);
        equals(principalId, field(session, "principal_id"), "verified session principal");
        equals(null, field(session, "secret_digest"),
                "the stored digest must not cross the boundary");

        equals("session_not_found", codeOf(() -> client.sessionVerify(sessionId, "nope")),
                "wrong session secret");
        client.sessionRevoke(sessionId, "test");
        equals("session_inactive", codeOf(() -> client.sessionVerify(sessionId, secret)),
                "revoked session");

        // An unknown identifier is indistinguishable from a known one.
        Object unknown = client.authnBegin(tenantId, "email", "ghost@example.com");
        equals(field(begun, "state"), field(unknown, "state"), "unknown identifier state");
        Object attempt = client.authnVerifyPassword(
                (String) field(unknown, "transaction_id"), password);
        equals(4L, field(attempt, "attempts_left"), "unknown identifier attempts");
        equals(null, field(attempt, "assurance"), "unknown identifier assurance");

        // Unknown records return stable codes rather than transport failures.
        equals("tenant_not_found", codeOf(() -> client.tenantGetByName("missing")), "missing tenant");
        equals("operation_not_found", codeOf(() -> client.request("identity.unknown", null)),
                "unknown operation");

        standardsDispatchScenario(client);
    }

    private static void standardsDispatchScenario(Sesame client) {
        Map<String, Object> endpoints = new LinkedHashMap<>();
        endpoints.put("authorization_endpoint", "/authorize");
        endpoints.put("token_endpoint", "/token");
        endpoints.put("jwks_uri", "/.well-known/jwks.json");
        endpoints.put("introspection_endpoint", "/introspect");
        endpoints.put("revocation_endpoint", "/revoke");
        endpoints.put("end_session_endpoint", "/logout");

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("contract_version", "unsupported");
        request.put("endpoint", "oidc.discovery");
        request.put("method", "GET");
        request.put("endpoints", endpoints);

        Object discovery = client.standardsDispatch(request);
        equals("1", field(discovery, "contract_version"), "standards contract version");
        equals(200L, field(discovery, "status"), "standards discovery status");
        equals("application/json", field(field(discovery, "headers"), "content-type"),
                "standards discovery content type");
        equals("https://id.example", field(field(discovery, "body"), "issuer"),
                "standards discovery issuer");
        equals("https://id.example/token", field(field(discovery, "body"), "token_endpoint"),
                "standards discovery token endpoint");

        Map<String, Object> unsupported = new LinkedHashMap<>();
        unsupported.put("endpoint", "oidc.userinfo");
        unsupported.put("method", "GET");
        equals("invalid_request", codeOf(() -> client.standardsDispatch(unsupported)),
                "unknown standards endpoint");
    }

    private static Object field(Object value, String key) {
        if (!(value instanceof Map)) {
            throw new AssertionError("expected an object, got " + value);
        }
        return ((Map<?, ?>) value).get(key);
    }

    private static String codeOf(Runnable action) {
        try {
            action.run();
        } catch (Sesame.ProtocolException error) {
            return error.code;
        }
        throw new AssertionError("expected a protocol error");
    }

    private static void equals(Object expected, Object actual, String what) {
        checks++;
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(what + ": expected " + expected + ", got " + actual);
        }
    }

    private static Path repositoryRoot() {
        Path candidate = Path.of("").toAbsolutePath();
        while (candidate != null) {
            if (Files.isRegularFile(candidate.resolve("go.mod"))) {
                return candidate;
            }
            candidate = candidate.getParent();
        }
        throw new IllegalStateException("could not locate the repository root");
    }

    private static Path build(Path root, Path workspace, String name, String source)
            throws IOException, InterruptedException {
        Path output = workspace.resolve(name);
        ProcessBuilder builder = new ProcessBuilder(
                "go", "build", "-trimpath", "-o", output.toString(), source);
        builder.directory(root.toFile());
        builder.environment().put("CGO_ENABLED", "0");
        builder.environment().put("GOTOOLCHAIN", "auto");
        builder.inheritIO();
        if (builder.start().waitFor() != 0) {
            throw new IllegalStateException("go build " + source + " failed");
        }
        return output;
    }

    private static Path initializeDeployment(
            Path root,
            Path workspace,
            Path sesameBinary,
            Path fakeFYLO) throws IOException, InterruptedException {
        Path deployment = workspace.resolve("deployment");
        ProcessBuilder builder = new ProcessBuilder(
                sesameBinary.toString(),
                "init",
                "--deployment", deployment.toString(),
                "--fylo-binary", fakeFYLO.toString(),
                "--issuer", "https://id.example");
        builder.directory(root.toFile());
        builder.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        builder.redirectError(ProcessBuilder.Redirect.INHERIT);
        if (builder.start().waitFor() != 0) {
            throw new IllegalStateException("sesame init failed");
        }
        return deployment;
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
        }
    }
}
