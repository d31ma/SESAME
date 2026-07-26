// Runs the shared SDK contract scenario against real compiled binaries.
//
// Every SESAME SDK drives this same sequence, so a divergence in any one
// client fails its own suite rather than hiding behind a mock. The harness is
// plain Kotlin: adding a test framework would contradict the shim's
// dependency-free promise.

package ma.del.sesame

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.system.exitProcess

private var checks = 0

private fun areEqual(expected: Any?, actual: Any?, what: String) {
    checks++
    if (expected?.toString() != actual?.toString()) {
        System.err.println("$what: expected $expected, got $actual")
        exitProcess(1)
    }
}

private fun field(value: Any?, key: String): Any? {
    val map = value as? Map<*, *> ?: run {
        System.err.println("expected an object, got $value")
        exitProcess(1)
    }
    return map[key]
}

private fun codeOf(action: () -> Unit): String {
    try {
        action()
    } catch (error: ProtocolException) {
        return error.code
    }
    System.err.println("expected a protocol error")
    exitProcess(1)
}

private fun repositoryRoot(): Path {
    var candidate: Path? = Path.of("").toAbsolutePath()
    while (candidate != null) {
        if (Files.isRegularFile(candidate.resolve("go.mod"))) return candidate
        candidate = candidate.parent
    }
    error("could not locate the repository root")
}

private fun build(root: Path, workspace: Path, name: String, source: String): Path {
    val output = workspace.resolve(name)
    val builder = ProcessBuilder("go", "build", "-trimpath", "-o", output.toString(), source)
        .directory(root.toFile())
        .inheritIO()
    builder.environment()["CGO_ENABLED"] = "0"
    builder.environment()["GOTOOLCHAIN"] = "auto"
    check(builder.start().waitFor() == 0) { "go build $source failed" }
    return output
}

private fun initializeDeployment(
    root: Path,
    workspace: Path,
    sesameBinary: Path,
    fakeFylo: Path,
): Path {
    val deployment = workspace.resolve("deployment")
    val builder = ProcessBuilder(
        sesameBinary.toString(),
        "init",
        "--deployment",
        deployment.toString(),
        "--fylo-binary",
        fakeFylo.toString(),
        "--issuer",
        "https://id.example",
    )
        .directory(root.toFile())
        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .redirectError(ProcessBuilder.Redirect.INHERIT)
    check(builder.start().waitFor() == 0) { "sesame init failed" }
    return deployment
}

fun main() {
    val root = repositoryRoot()
    val workspace = Files.createTempDirectory("sesame-kotlin-contract-")
    try {
        val sesameBinary = build(root, workspace, "sesame", "./cmd/sesame")
        val fakeFylo = build(
            root, workspace, "fake-fylo", "./internal/adapters/fylo/testdata/fakefylo",
        )
        val deployment = initializeDeployment(root, workspace, sesameBinary, fakeFylo)

        Client(
            Options(
                binary = sesameBinary.toString(),
                deployment = deployment.toString(),
            ),
        ).use { client ->
            // System operations report a storage-backed process.
            areEqual("ok", field(client.ping(), "status"), "ping status")
            areEqual("ok", field(client.readiness(), "status"), "readiness status")
            areEqual("sesame", field(client.version(), "name"), "version name")
            areEqual(true, field(client.metrics(), "storage_configured"), "storage configured")

            // Tenant and principal.
            val tenantId = field(field(client.tenantBootstrap("acme"), "tenant"), "tenant_id")
                as String
            val principal = client.principalCreate(tenantId, "human", "email", "Alice@Example.com")
            val principalId = field(principal, "principal_id") as String
            areEqual(
                "alice@example.com",
                field(field(principal, "identifier"), "value"),
                "the engine normalizes the identifier",
            )

            // A duplicate claim returns the stable conflict code.
            areEqual(
                "identifier_conflict",
                codeOf {
                    client.principalCreate(tenantId, "workload", "email", "alice@example.com")
                },
                "duplicate identifier",
            )

            // Authorization: deny by default, allow after a grant, deny after revoke.
            val roleId = field(
                client.roleCreate(
                    tenantId,
                    "reader",
                    listOf(mapOf("action" to "doc:read", "resource" to "project:*")),
                ),
                "role_id",
            ) as String

            val denied = client.decide(tenantId, principalId, "doc:read", "project:alpha")
            areEqual("deny", field(denied, "decision"), "pre-grant decision")
            areEqual("deny_no_grant", field(denied, "reason_code"), "pre-grant reason")

            val grantId = field(
                client.grantCreate(tenantId, principalId, roleId), "grant_id",
            ) as String
            val allowed = client.decide(tenantId, principalId, "doc:read", "project:alpha")
            areEqual("allow", field(allowed, "decision"), "post-grant decision")
            areEqual("allow_role_grant", field(allowed, "reason_code"), "post-grant reason")

            client.grantRevoke(grantId)
            areEqual(
                "deny",
                field(client.decide(tenantId, principalId, "doc:read", "project:alpha"), "decision"),
                "post-revoke decision",
            )

            // Authentication: password login, session verification, revocation.
            val password = "correct horse battery staple"
            client.setPassword(principalId, password)
            val begun = client.authnBegin(tenantId, "email", "Alice@Example.com")
            areEqual("awaiting_factor", field(begun, "state"), "begin state")
            val transactionId = field(begun, "transaction_id") as String

            val wrong = client.authnVerifyPassword(transactionId, "wrong password value")
            areEqual(4L, field(wrong, "attempts_left"), "attempts after a wrong password")

            val verified = client.authnVerifyPassword(transactionId, password)
            areEqual("password", field(verified, "assurance"), "assurance")

            val issued = client.authnComplete(transactionId, 3600)
            val sessionId = field(issued, "session_id") as String
            val secret = field(issued, "session_secret") as String

            val session = client.sessionVerify(sessionId, secret)
            areEqual(principalId, field(session, "principal_id"), "verified session principal")
            areEqual(
                null,
                field(session, "secret_digest"),
                "the stored digest must not cross the boundary",
            )

            areEqual(
                "session_not_found",
                codeOf { client.sessionVerify(sessionId, "nope") },
                "wrong session secret",
            )
            client.sessionRevoke(sessionId, "test")
            areEqual(
                "session_inactive",
                codeOf { client.sessionVerify(sessionId, secret) },
                "revoked session",
            )

            // An unknown identifier is indistinguishable from a known one.
            val unknown = client.authnBegin(tenantId, "email", "ghost@example.com")
            areEqual(field(begun, "state"), field(unknown, "state"), "unknown identifier state")
            val attempt = client.authnVerifyPassword(
                field(unknown, "transaction_id") as String, password,
            )
            areEqual(4L, field(attempt, "attempts_left"), "unknown identifier attempts")
            areEqual(null, field(attempt, "assurance"), "unknown identifier assurance")

            // Unknown records return stable codes rather than transport failures.
            areEqual(
                "tenant_not_found",
                codeOf { client.tenantGetByName("missing") },
                "missing tenant",
            )
            areEqual(
                "operation_not_found",
                codeOf { client.request("identity.unknown") },
                "unknown operation",
            )

            standardsDispatchScenario(client)
        }
        println("ok\tkotlin contract scenario\t$checks checks")
    } finally {
        workspace.toFile().walkBottomUp().forEach(File::delete)
    }
}

private fun standardsDispatchScenario(client: Client) {
    val endpoints = mapOf(
        "authorization_endpoint" to "/authorize",
        "token_endpoint" to "/token",
        "jwks_uri" to "/.well-known/jwks.json",
        "introspection_endpoint" to "/introspect",
        "revocation_endpoint" to "/revoke",
        "end_session_endpoint" to "/logout",
    )
    val discovery = client.standardsDispatch(
        mapOf(
            "contract_version" to "unsupported",
            "endpoint" to "oidc.discovery",
            "method" to "GET",
            "endpoints" to endpoints,
        ),
    )
    areEqual("1", field(discovery, "contract_version"), "standards contract version")
    areEqual(200L, field(discovery, "status"), "standards discovery status")
    areEqual(
        "application/json",
        field(field(discovery, "headers"), "content-type"),
        "standards discovery content type",
    )
    areEqual(
        "https://id.example",
        field(field(discovery, "body"), "issuer"),
        "standards discovery issuer",
    )
    areEqual(
        "https://id.example/token",
        field(field(discovery, "body"), "token_endpoint"),
        "standards discovery token endpoint",
    )

    areEqual(
        "invalid_request",
        codeOf {
            client.standardsDispatch(
                mapOf("endpoint" to "oidc.userinfo", "method" to "GET"),
            )
        },
        "unknown standards endpoint",
    )
}
