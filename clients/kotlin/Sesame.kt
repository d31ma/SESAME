// A thin Kotlin client for a local SESAME process.
//
// The client owns process lifecycle, NDJSON framing, and typed transport
// errors. Identity and authorization semantics remain in the SESAME
// executable. Dependencies: the JVM standard library only, so the shim
// carries a small JSON reader and writer that handles the protocol's shapes
// and rejects the rest.
//
// This is a server-side shim: it spawns the SESAME binary. SESAME has no
// embeddable engine and no browser or on-device variant, because a device
// copy could never be authoritative for shared security state.

package ma.del.sesame

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.util.concurrent.TimeUnit

const val PROTOCOL_VERSION: String = "1"
const val MAX_FRAME_BYTES: Int = 1 shl 20

/** A stable error returned by the SESAME machine interface. */
class ProtocolException(
    val code: String,
    val detail: String,
    val retryable: Boolean = false,
) : RuntimeException("sesame protocol error $code: $detail")

/** A transport or framing failure. */
class TransportException(detail: String) : RuntimeException("sesame transport error: $detail")

/**
 * A startup failure carrying what the engine said before it exited. The
 * message is already complete, so nothing is prefixed onto it.
 */
class StartupException(message: String, cause: Throwable) : RuntimeException(message, cause)

/**
 * A SESAME binary this client cannot speak to. It names both sides, because
 * the fix is always to change one of them.
 */
class IncompatibleEngineException(
    val clientProtocolVersion: String,
    val engineProtocolVersion: String,
    val engineVersion: String,
    val missingOperations: List<String> = emptyList(),
) : RuntimeException(
    if (engineProtocolVersion != clientProtocolVersion) {
        "sesame engine $engineVersion speaks machine protocol " +
            "\"$engineProtocolVersion\"; this client speaks \"$clientProtocolVersion\""
    } else {
        "sesame engine $engineVersion does not support ${missingOperations.size} " +
            "operation(s) this client requires: ${missingOperations.joinToString(", ")}"
    },
)

/** Startup options for the local SESAME process. */
data class Options(
    /** Empty means: SESAME_BINARY, then "sesame" on PATH. */
    val binary: String = "",
    val deployment: String? = null,
    val fyloBinary: String? = null,
    val fyloRoot: String? = null,
    /**
     * Suppresses the protocol handshake the constructor performs. For tests
     * that deliberately drive a mismatched engine; production callers leave it
     * false.
     */
    val skipCompatibilityCheck: Boolean = false,
)

/** Owns one long-lived local SESAME subprocess. */
class Client(options: Options) : AutoCloseable {
    private val process: Process
    private val stdin: BufferedWriter
    private val stdout: BufferedReader
    private var counter = 0L
    private var closed = false

    init {
        val arguments = buildList {
            // SESAME_BINARY names the engine when no option does; an explicit option still wins.
            add(options.binary.ifEmpty { System.getenv("SESAME_BINARY") ?: "sesame" })
            add("exec")
            add("--loop")
            if (!options.deployment.isNullOrEmpty()) {
                add("--deployment")
                add(options.deployment)
            }
            if (!options.fyloBinary.isNullOrEmpty() || !options.fyloRoot.isNullOrEmpty()) {
                add("--fylo-binary")
                add(options.fyloBinary.orEmpty())
                add("--fylo-root")
                add(options.fyloRoot.orEmpty())
            }
        }
        process = try {
            // The engine reports a missing deployment or an unusable FYLO root
            // on stderr and then exits. Discarding that would leave the caller
            // with a dead process and no reason.
            ProcessBuilder(arguments)
                .start()
        } catch (error: Exception) {
            throw TransportException("start sesame: ${error.message}")
        }
        stdin = BufferedWriter(OutputStreamWriter(process.outputStream, Charsets.UTF_8))
        stdout = BufferedReader(InputStreamReader(process.inputStream, Charsets.UTF_8))

        // A mismatched engine is found here rather than partway through a
        // security flow that then cannot finish. system.version needs no
        // storage, so this works before a FYLO root is configured.
        if (!options.skipCompatibilityCheck) {
            try {
                checkCompatibility()
            } catch (error: RuntimeException) {
                val diagnostic = startupDiagnostics()
                close()
                if (diagnostic.isNotEmpty()) {
                    // A TransportException prefixes its own message, so
                    // wrapping one in another would print the prefix twice.
                    throw StartupException("${error.message}: $diagnostic", error)
                }
                throw error
            }
        }
        // The engine is up; an undrained stderr pipe would eventually block it.
        Thread { process.errorStream.use { it.readBytes() } }
            .apply { isDaemon = true }
            .start()
    }

    /** Reads what a failing engine said before it exited. */
    private fun startupDiagnostics(): String =
        runCatching {
            val buffer = ByteArray(STARTUP_DIAGNOSTICS_BYTES)
            val read = process.errorStream.read(buffer)
            if (read <= 0) "" else String(buffer, 0, read, Charsets.UTF_8).trim()
        }.getOrDefault("")

    /** Fails unless the engine speaks this client's machine protocol. */
    fun checkCompatibility(): Any? {
        val info = version() as? Map<*, *> ?: throw TransportException("version is not an object")
        val engine = info["protocol_version"]?.toString().orEmpty()
        if (engine != PROTOCOL_VERSION) {
            throw IncompatibleEngineException(
                PROTOCOL_VERSION,
                engine,
                info["version"]?.toString().orEmpty(),
            )
        }
        return info
    }

    /**
     * Fails unless the engine routes every named operation. Call it at startup
     * with what the application depends on: finding out here beats an
     * operation_not_found in the middle of a login.
     */
    fun requireOperations(vararg operations: String): Any? {
        val info = version() as? Map<*, *> ?: throw TransportException("version is not an object")
        val routed = (info["operations"] as? List<*>)?.map { it.toString() }.orEmpty().toSet()
        val missing = operations.filterNot(routed::contains).sorted()
        if (missing.isNotEmpty()) {
            throw IncompatibleEngineException(
                PROTOCOL_VERSION,
                info["protocol_version"]?.toString().orEmpty(),
                info["version"]?.toString().orEmpty(),
                missing,
            )
        }
        return info
    }

    /** Sends one operation and returns its result. */
    fun request(operation: String, parameters: Map<String, Any?> = emptyMap()): Any? {
        if (closed) throw TransportException("sesame client is closed")

        counter++
        val requestId = "kt-${System.nanoTime()}-$counter"
        val envelope = linkedMapOf<String, Any?>(
            "protocol_version" to PROTOCOL_VERSION,
            "request_id" to requestId,
            "operation" to operation,
            "parameters" to parameters,
        )
        val frame = Json.write(envelope)
        if (frame.toByteArray(Charsets.UTF_8).size > MAX_FRAME_BYTES) {
            throw TransportException("request exceeds the maximum frame size")
        }

        try {
            stdin.write(frame)
            stdin.write("\n")
            stdin.flush()
        } catch (error: Exception) {
            throw TransportException("write request: ${error.message}")
        }

        val line = try {
            stdout.readLine()
        } catch (error: Exception) {
            throw TransportException("read response: ${error.message}")
        } ?: throw TransportException("sesame process exited")

        return decodeResponse(requestId, line)
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            stdin.close()
            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroyForcibly()
            }
        } catch (error: Exception) {
            process.destroyForcibly()
            if (error is InterruptedException) Thread.currentThread().interrupt()
        }
    }

    // System operations.
    fun ping(): Any? = request("system.ping")
    fun version(): Any? = request("system.version")
    fun readiness(): Any? = request("system.readiness")
    fun metrics(): Any? = request("system.metrics")

    // Tenants and principals.
    fun tenantBootstrap(name: String): Any? =
        request("tenant.bootstrap", mapOf("name" to name))

    fun tenantGetByName(name: String): Any? = request("tenant.get", mapOf("name" to name))

    fun principalCreate(
        tenantId: String,
        kind: String,
        namespace: String,
        value: String,
    ): Any? = request(
        "principal.create",
        mapOf(
            "tenant_id" to tenantId,
            "kind" to kind,
            "identifier_namespace" to namespace,
            "identifier_value" to value,
        ),
    )

    fun principalGetById(principalId: String): Any? =
        request("principal.get", mapOf("principal_id" to principalId))

    fun principalSuspend(principalId: String): Any? =
        request("principal.suspend", mapOf("principal_id" to principalId))

    // Authorization.
    fun roleCreate(
        tenantId: String,
        name: String,
        permissions: List<Map<String, Any?>>,
    ): Any? = request(
        "role.create",
        mapOf("tenant_id" to tenantId, "name" to name, "permissions" to permissions),
    )

    fun grantCreate(tenantId: String, principalId: String, roleId: String): Any? = request(
        "grant.create",
        mapOf("tenant_id" to tenantId, "principal_id" to principalId, "role_id" to roleId),
    )

    fun grantRevoke(grantId: String): Any? =
        request("grant.revoke", mapOf("grant_id" to grantId))

    // Asks the same question as decide, but proves a session instead of naming a principal.
    //
    // The engine verifies the session and derives context under the reserved
    // "session." prefix, so a caller cannot assert its own assurance level. That
    // is what makes a step-up condition worth trusting.
    fun decideForSession(
        tenantId: String,
        sessionId: String,
        sessionSecret: String,
        action: String,
        resource: String,
    ): Any? = request(
        "authorize.decide",
        mapOf(
            "tenant_id" to tenantId,
            "session_id" to sessionId,
            "session_secret" to sessionSecret,
            "action" to action,
            "resource" to resource,
        ),
    )

    fun decide(tenantId: String, principalId: String, action: String, resource: String): Any? =
        request(
            "authorize.decide",
            mapOf(
                "tenant_id" to tenantId,
                "principal_id" to principalId,
                "action" to action,
                "resource" to resource,
            ),
        )

    // Authentication.
    fun setPassword(principalId: String, password: String): Any? = request(
        "authenticator.set_password",
        mapOf("principal_id" to principalId, "password" to password),
    )

    /**
     * Starts a login transaction. It succeeds whether or not the identifier
     * resolves, so the result never reveals which identifiers exist.
     */
    fun authnBegin(tenantId: String, namespace: String, value: String): Any? = request(
        "authn.begin",
        mapOf(
            "tenant_id" to tenantId,
            "identifier_namespace" to namespace,
            "identifier_value" to value,
        ),
    )

    fun authnVerifyPassword(transactionId: String, password: String): Any? = request(
        "authn.verify_password",
        mapOf("transaction_id" to transactionId, "password" to password),
    )

    fun authnComplete(transactionId: String, lifetimeSeconds: Long = 0): Any? = request(
        "authn.complete",
        mapOf("transaction_id" to transactionId, "lifetime_seconds" to lifetimeSeconds),
    )

    fun sessionVerify(sessionId: String, secret: String): Any? = request(
        "session.verify",
        mapOf("session_id" to sessionId, "session_secret" to secret),
    )

    fun sessionRevoke(sessionId: String, reason: String = ""): Any? = request(
        "session.revoke",
        mapOf("session_id" to sessionId, "reason" to reason),
    )

    // Groups and administration.
    fun groupCreate(tenantId: String, name: String): Any? = request(
        "group.create",
        mapOf("tenant_id" to tenantId, "name" to name),
    )

    fun groupMemberAdd(groupId: String, principalId: String): Any? = request(
        "group.member_add",
        mapOf("group_id" to groupId, "principal_id" to principalId),
    )

    fun groupMemberRemove(groupId: String, principalId: String): Any? = request(
        "group.member_remove",
        mapOf("group_id" to groupId, "principal_id" to principalId),
    )

    fun adminBootstrap(tenantName: String, namespace: String, value: String): Any? = request(
        "admin.bootstrap",
        mapOf(
            "tenant_name" to tenantName,
            "identifier_namespace" to namespace,
            "identifier_value" to value,
        ),
    )

    /** A batch always answers under one policy version. */
    fun decideBatch(requests: List<Map<String, Any?>>): Any? = request(
        "authorize.decide_batch",
        mapOf("requests" to requests),
    )

    // Second factors. The TOTP shared secret is returned once at enrolment and
    // is never recoverable afterwards; a used code spends its time step
    // durably, so an observed code cannot be replayed inside its own window.
    fun totpEnroll(principalId: String, issuer: String = "SESAME"): Any? = request(
        "authenticator.totp_enroll",
        mapOf("principal_id" to principalId, "issuer" to issuer),
    )

    fun totpActivate(principalId: String, code: String): Any? = request(
        "authenticator.totp_activate",
        mapOf("principal_id" to principalId, "code" to code),
    )

    fun authnVerifyTotp(transactionId: String, code: String): Any? = request(
        "authn.verify_totp",
        mapOf("transaction_id" to transactionId, "code" to code),
    )

    /** Returns ten single-use codes once, retiring any previous set. */
    fun recoveryCodesIssue(principalId: String): Any? = request(
        "authenticator.recovery_codes_issue",
        mapOf("principal_id" to principalId),
    )

    fun authnVerifyRecoveryCode(transactionId: String, code: String): Any? = request(
        "authn.verify_recovery_code",
        mapOf("transaction_id" to transactionId, "code" to code),
    )

    // OIDC relying parties. An omitted audience is treated as third party, the
    // stricter rule: such a client needs recorded user consent before it
    // receives an authorization code.
    fun oidcClientRegister(
        tenantId: String,
        name: String,
        clientType: String,
        redirectUris: List<String>,
        scopes: List<String> = emptyList(),
        audience: String = "",
        postLogoutRedirectUris: List<String> = emptyList(),
    ): Any? = request(
        "oidc_client.register",
        mapOf(
            "tenant_id" to tenantId,
            "name" to name,
            "client_type" to clientType,
            "redirect_uris" to redirectUris,
            "scopes" to scopes,
            "audience" to audience,
            "post_logout_redirect_uris" to postLogoutRedirectUris,
        ),
    )

    fun oidcClientGet(clientId: String): Any? = request(
        "oidc_client.get",
        mapOf("client_id" to clientId),
    )

    fun oidcClientRotateSecret(clientId: String): Any? = request(
        "oidc_client.rotate_secret",
        mapOf("client_id" to clientId),
    )

    fun oidcClientDisable(clientId: String, reason: String = ""): Any? = request(
        "oidc_client.disable",
        mapOf("client_id" to clientId, "reason" to reason),
    )

    // The external interaction contract. authorize validates the whole request
    // before anything is shown to a user; the returned secret authorizes
    // completing that one interaction.
    fun authorize(authorizationRequest: Map<String, Any?>): Any? =
        request("oidc.authorize", authorizationRequest)

    fun interactionGet(interactionId: String): Any? = request(
        "oidc.interaction_get",
        mapOf("interaction_id" to interactionId),
    )

    fun interactionComplete(
        interactionId: String,
        interactionSecret: String,
        sessionId: String,
        sessionSecret: String,
    ): Any? = request(
        "oidc.interaction_complete",
        mapOf(
            "interaction_id" to interactionId,
            "interaction_secret" to interactionSecret,
            "session_id" to sessionId,
            "session_secret" to sessionSecret,
        ),
    )

    /**
     * A refresh response carries a new refresh token that replaces the one
     * presented; continuing to use the old one revokes the whole family.
     */
    // The device grant (RFC 8628). deviceAuthorize starts it; the person types
    // the user code elsewhere and approves or denies it there.
    fun dpopVerify(accessToken: String, proof: String, method: String, uri: String): Any? =
        request(
            "oidc.dpop_verify",
            mapOf(
                "access_token" to accessToken,
                "dpop_proof" to proof,
                "http_method" to method,
                "http_uri" to uri,
            ),
        )

    fun pushedAuthorize(request: Map<String, Any?>): Any? =
        request("oidc.pushed_authorize", request)

    fun deviceAuthorize(clientId: String, scopes: List<String> = emptyList()): Any? =
        request("oidc.device_authorize", mapOf("client_id" to clientId, "scopes" to scopes))

    fun deviceLookup(tenantId: String, userCode: String): Any? =
        request("oidc.device_lookup", mapOf("tenant_id" to tenantId, "user_code" to userCode))

    fun deviceApprove(
        tenantId: String,
        userCode: String,
        sessionId: String,
        sessionSecret: String,
    ): Any? = request(
        "oidc.device_approve",
        mapOf(
            "tenant_id" to tenantId,
            "user_code" to userCode,
            "session_id" to sessionId,
            "session_secret" to sessionSecret,
        ),
    )

    fun deviceDeny(tenantId: String, userCode: String): Any? =
        request("oidc.device_deny", mapOf("tenant_id" to tenantId, "user_code" to userCode))

    fun tokenExchange(tokenRequest: Map<String, Any?>): Any? =
        request("oidc.token", tokenRequest)

    fun refreshFamilyRevoke(familyId: String, reason: String = ""): Any? = request(
        "oidc.refresh_family_revoke",
        mapOf("family_id" to familyId, "reason" to reason),
    )

    fun refreshFamilyGet(familyId: String): Any? = request(
        "oidc.refresh_family_get",
        mapOf("family_id" to familyId),
    )

    // Consent. The session proves who is agreeing, so a caller cannot consent
    // on somebody else's behalf. Withdrawing also revokes that client's refresh
    // families for the principal.
    fun consentGrant(
        sessionId: String,
        sessionSecret: String,
        clientId: String,
        scopes: List<String>,
    ): Any? = request(
        "oidc.consent_grant",
        mapOf(
            "session_id" to sessionId,
            "session_secret" to sessionSecret,
            "client_id" to clientId,
            "scopes" to scopes,
        ),
    )

    fun consentWithdraw(principalId: String, clientId: String): Any? = request(
        "oidc.consent_withdraw",
        mapOf("principal_id" to principalId, "client_id" to clientId),
    )

    fun consentGet(principalId: String, clientId: String): Any? = request(
        "oidc.consent_get",
        mapOf("principal_id" to principalId, "client_id" to clientId),
    )

    // Standards surfaces. Endpoint paths are the host's own; the engine
    // composes them under the configured issuer and refuses any that would
    // leave that origin.
    fun standardsDispatch(request: Map<String, Any?>): Any? =
        this.request("standards.dispatch", request + ("contract_version" to "1"))

    fun discovery(endpoints: Map<String, Any?> = emptyMap()): Any? =
        request("oidc.discovery", endpoints)

    fun signingKeys(): Any? = request("token.jwks", emptyMap())

    /**
     * Introspection reports live grant state, not just signature validity:
     * this is where a revoked session shows up.
     */
    fun introspect(clientId: String, clientSecret: String, token: String): Any? = request(
        "oidc.introspect",
        mapOf("token" to token, "client_id" to clientId, "client_secret" to clientSecret),
    )

    fun revoke(clientId: String, clientSecret: String, token: String): Any? = request(
        "oidc.revoke",
        mapOf("token" to token, "client_id" to clientId, "client_secret" to clientSecret),
    )

    /**
     * The hint is required and may be expired; revoking its session also ends
     * every refresh grant resting on it.
     */
    fun logout(
        idTokenHint: String,
        postLogoutRedirectUri: String = "",
        state: String = "",
    ): Any? = request(
        "oidc.logout",
        mapOf(
            "id_token_hint" to idTokenHint,
            "post_logout_redirect_uri" to postLogoutRedirectUri,
            "state" to state,
        ),
    )

    // Passkeys. Binary values cross the protocol as base64. A user-verified
    // passkey establishes MFA on its own, with no prior factor.
    fun passkeyRegisterBegin(principalId: String): Any? = request(
        "authenticator.passkey_register_begin",
        mapOf("principal_id" to principalId),
    )

    fun passkeyRegisterFinish(
        principalId: String,
        attestationObject: ByteArray,
        clientDataJson: ByteArray,
    ): Any? = request(
        "authenticator.passkey_register_finish",
        mapOf(
            "principal_id" to principalId,
            "attestation_object" to base64Url(attestationObject),
            "client_data_json" to base64Url(clientDataJson),
        ),
    )

    fun passkeyList(principalId: String): Any? = request(
        "authenticator.passkey_list",
        mapOf("principal_id" to principalId),
    )

    fun passkeyRemove(credentialId: String): Any? = request(
        "authenticator.passkey_remove",
        mapOf("credential_id" to credentialId),
    )

    fun passkeyOptions(transactionId: String): Any? = request(
        "authn.passkey_options",
        mapOf("transaction_id" to transactionId),
    )

    fun authnVerifyPasskey(
        transactionId: String,
        credentialId: String,
        authenticatorData: ByteArray,
        clientDataJson: ByteArray,
        signature: ByteArray,
    ): Any? = request(
        "authn.verify_passkey",
        mapOf(
            "transaction_id" to transactionId,
            "credential_id" to credentialId,
            "authenticator_data" to base64Url(authenticatorData),
            "client_data_json" to base64Url(clientDataJson),
            "signature" to base64Url(signature),
        ),
    )

    // Inbound OIDC federation. The engine performs no network I/O: register and
    // configure return the exact URL the host must fetch, and every document
    // the host brings back is validated in the engine as untrusted input.
    // SCIM 2.0 provisioning. Every resource operation carries the bearer token,
    // so the engine always authenticates and a host cannot forget to.
    fun provisioningClientRegister(
        tenantId: String,
        name: String,
        identifierNamespace: String = "",
        canManageGroups: Boolean = false,
    ): Any? = request(
        "scim.client_register",
        mapOf(
            "tenant_id" to tenantId,
            "name" to name,
            "identifier_namespace" to identifierNamespace,
            "can_manage_groups" to canManageGroups,
        ),
    )

    fun provisioningClientDisable(
        tenantId: String,
        scimClientId: String,
        reason: String = "",
    ): Any? = request(
        "scim.client_disable",
        mapOf("tenant_id" to tenantId, "scim_client_id" to scimClientId, "reason" to reason),
    )

    fun provisioningClientRotateToken(tenantId: String, scimClientId: String): Any? = request(
        "scim.client_rotate_token",
        mapOf("tenant_id" to tenantId, "scim_client_id" to scimClientId),
    )

    // SCIM Group provisioning. These require the client's can_manage_groups
    // grant: group membership drives authorization decisions.
    fun scimGroupCreate(token: String, body: String): Any? =
        request("scim.group_create", mapOf("token" to token, "body" to body))

    fun scimGroupGet(token: String, resourceId: String): Any? =
        request("scim.group_get", mapOf("token" to token, "resource_id" to resourceId))

    fun scimGroupList(
        token: String,
        filter: String = "",
        startIndex: Long = 1,
        count: Long = 0,
    ): Any? = request(
        "scim.group_list",
        mapOf(
            "token" to token,
            "filter" to filter,
            "start_index" to startIndex,
            "count" to count,
        ),
    )

    fun scimGroupPatch(token: String, resourceId: String, body: String): Any? = request(
        "scim.group_patch",
        mapOf("token" to token, "resource_id" to resourceId, "body" to body),
    )

    fun scimGroupDeprovision(token: String, resourceId: String): Any? =
        request("scim.group_deprovision", mapOf("token" to token, "resource_id" to resourceId))

    fun scimUserCreate(token: String, body: String): Any? =
        request("scim.user_create", mapOf("token" to token, "body" to body))

    fun scimUserGet(token: String, resourceId: String): Any? =
        request("scim.user_get", mapOf("token" to token, "resource_id" to resourceId))

    fun scimUserList(
        token: String,
        filter: String = "",
        startIndex: Long = 1,
        count: Long = 0,
    ): Any? = request(
        "scim.user_list",
        mapOf(
            "token" to token,
            "filter" to filter,
            "start_index" to startIndex,
            "count" to count,
        ),
    )

    fun scimUserPatch(token: String, resourceId: String, body: String): Any? = request(
        "scim.user_patch",
        mapOf("token" to token, "resource_id" to resourceId, "body" to body),
    )

    fun scimUserDeprovision(token: String, resourceId: String): Any? =
        request("scim.user_deprovision", mapOf("token" to token, "resource_id" to resourceId))

    fun providerRegister(
        tenantId: String,
        name: String,
        issuer: String,
        clientId: String,
        clientSecret: String,
        scopes: List<String>,
        subjectClaim: String = "sub",
        emailClaim: String = "",
        linking: String = "strict",
    ): Any? = request(
        "federation.provider_register",
        mapOf(
            "tenant_id" to tenantId,
            "name" to name,
            "issuer" to issuer,
            "client_id" to clientId,
            "client_secret" to clientSecret,
            "scopes" to scopes,
            "subject_claim" to subjectClaim,
            "email_claim" to emailClaim,
            "linking" to linking,
        ),
    )

    fun samlProviderRegister(
        tenantId: String,
        name: String,
        entityId: String,
        ssoUrl: String,
        certificates: List<String>,
        identifierNamespace: String = "email",
        linking: String = "strict",
    ): Any? = request(
        "saml.provider_register",
        mapOf(
            "tenant_id" to tenantId,
            "name" to name,
            "entity_id" to entityId,
            "sso_url" to ssoUrl,
            "certificates" to certificates,
            "identifier_namespace" to identifierNamespace,
            "linking" to linking,
        ),
    )

    fun samlProviderGet(tenantId: String, providerId: String): Any? =
        request("saml.provider_get", mapOf("tenant_id" to tenantId, "provider_id" to providerId))

    fun samlProviderDisable(tenantId: String, providerId: String, reason: String = ""): Any? =
        request(
            "saml.provider_disable",
            mapOf("tenant_id" to tenantId, "provider_id" to providerId, "reason" to reason),
        )

    fun samlLoginStart(tenantId: String, providerId: String, consumerUrl: String): Any? =
        request(
            "saml.login_start",
            mapOf(
                "tenant_id" to tenantId,
                "provider_id" to providerId,
                "consumer_url" to consumerUrl,
            ),
        )

    fun samlLoginComplete(tenantId: String, loginId: String, assertion: String): Any? =
        request(
            "saml.login_complete",
            mapOf("tenant_id" to tenantId, "login_id" to loginId, "assertion" to assertion),
        )

    fun providerConfigure(
        tenantId: String,
        providerId: String,
        discoveryDocument: String,
        keySetDocument: String,
    ): Any? = request(
        "federation.provider_configure",
        mapOf(
            "tenant_id" to tenantId,
            "provider_id" to providerId,
            "discovery_document" to discoveryDocument,
            "key_set_document" to keySetDocument,
        ),
    )

    fun providerDisable(tenantId: String, providerId: String, reason: String = ""): Any? = request(
        "federation.provider_disable",
        mapOf("tenant_id" to tenantId, "provider_id" to providerId, "reason" to reason),
    )

    fun providerGet(tenantId: String, providerId: String): Any? = request(
        "federation.provider_get",
        mapOf("tenant_id" to tenantId, "provider_id" to providerId),
    )

    fun federatedLoginStart(tenantId: String, providerId: String, redirectUri: String): Any? =
        request(
            "federation.login_start",
            mapOf(
                "tenant_id" to tenantId,
                "provider_id" to providerId,
                "redirect_uri" to redirectUri,
            ),
        )

    fun federatedLoginExchange(
        tenantId: String,
        loginId: String,
        state: String,
        code: String,
    ): Any? = request(
        "federation.login_exchange",
        mapOf(
            "tenant_id" to tenantId,
            "login_id" to loginId,
            "state" to state,
            "code" to code,
        ),
    )

    fun federatedLoginComplete(tenantId: String, loginId: String, idToken: String): Any? = request(
        "federation.login_complete",
        mapOf("tenant_id" to tenantId, "login_id" to loginId, "id_token" to idToken),
    )

    private companion object {
        /**
         * Bounds what a failing engine can make the caller hold: generous
         * enough for a refusal and its remedy, short of anything worrying.
         */
        const val STARTUP_DIAGNOSTICS_BYTES = 4096

        /** Encodes a binary WebAuthn value for transport, without padding. */
        fun base64Url(value: ByteArray): String =
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value)

        fun decodeResponse(requestId: String, line: String): Any? {
            val response = Json.read(line) as? Map<*, *>
                ?: throw TransportException("response is not a JSON object")
            if (response["protocol_version"] != PROTOCOL_VERSION) {
                throw TransportException("unsupported protocol version")
            }
            if (response["request_id"] != requestId) {
                throw TransportException("response request ID mismatch")
            }
            val ok = response["ok"] as? Boolean
                ?: throw TransportException("response has no ok field")
            if (!ok) {
                val error = response["error"] as? Map<*, *>
                    ?: throw TransportException("failure response has no error")
                throw ProtocolException(
                    error["code"]?.toString().orEmpty(),
                    error["message"]?.toString().orEmpty(),
                    error["retryable"] == true,
                )
            }
            return response["result"]
        }
    }
}

/** A minimal JSON reader and writer for the protocol's shapes. */
internal object Json {
    fun write(value: Any?): String = StringBuilder().also { writeValue(value, it) }.toString()

    private fun writeValue(value: Any?, out: StringBuilder) {
        when (value) {
            null -> out.append("null")
            is String -> writeString(value, out)
            is Boolean, is Int, is Long -> out.append(value)
            is Double, is Float -> {
                val number = (value as Number).toDouble()
                if (number == Math.rint(number) && Math.abs(number) < 9.0e15) {
                    out.append(number.toLong())
                } else {
                    out.append(number)
                }
            }
            is Map<*, *> -> {
                out.append('{')
                value.entries.forEachIndexed { index, entry ->
                    if (index > 0) out.append(',')
                    writeString(entry.key.toString(), out)
                    out.append(':')
                    writeValue(entry.value, out)
                }
                out.append('}')
            }
            is List<*> -> {
                out.append('[')
                value.forEachIndexed { index, item ->
                    if (index > 0) out.append(',')
                    writeValue(item, out)
                }
                out.append(']')
            }
            else -> throw TransportException("unsupported JSON value ${value::class}")
        }
    }

    private fun writeString(text: String, out: StringBuilder) {
        out.append('"')
        for (character in text) {
            when {
                character == '"' -> out.append("\\\"")
                character == '\\' -> out.append("\\\\")
                character == '\n' -> out.append("\\n")
                character == '\r' -> out.append("\\r")
                character == '\t' -> out.append("\\t")
                character.code < 0x20 -> out.append("\\u%04x".format(character.code))
                else -> out.append(character)
            }
        }
        out.append('"')
    }

    fun read(text: String): Any? {
        val cursor = intArrayOf(0)
        val value = readValue(text, cursor)
        skipWhitespace(text, cursor)
        if (cursor[0] != text.length) {
            throw TransportException("trailing content after JSON value")
        }
        return value
    }

    private fun skipWhitespace(text: String, cursor: IntArray) {
        while (cursor[0] < text.length && text[cursor[0]].isWhitespace()) cursor[0]++
    }

    private fun readValue(text: String, cursor: IntArray): Any? {
        skipWhitespace(text, cursor)
        if (cursor[0] >= text.length) throw TransportException("unexpected end of JSON input")
        return when (text[cursor[0]]) {
            '{' -> readObject(text, cursor)
            '[' -> readArray(text, cursor)
            '"' -> readString(text, cursor)
            't' -> readLiteral(text, cursor, "true", true)
            'f' -> readLiteral(text, cursor, "false", false)
            'n' -> readLiteral(text, cursor, "null", null)
            else -> readNumber(text, cursor)
        }
    }

    private fun readLiteral(text: String, cursor: IntArray, literal: String, value: Any?): Any? {
        if (!text.startsWith(literal, cursor[0])) throw TransportException("expected $literal")
        cursor[0] += literal.length
        return value
    }

    private fun readObject(text: String, cursor: IntArray): Map<String, Any?> {
        cursor[0]++
        val fields = LinkedHashMap<String, Any?>()
        skipWhitespace(text, cursor)
        if (cursor[0] < text.length && text[cursor[0]] == '}') {
            cursor[0]++
            return fields
        }
        while (true) {
            skipWhitespace(text, cursor)
            val key = readString(text, cursor)
            skipWhitespace(text, cursor)
            if (cursor[0] >= text.length || text[cursor[0]] != ':') {
                throw TransportException("expected ':' in object")
            }
            cursor[0]++
            val value = readValue(text, cursor)
            // A duplicate key is ambiguous, so it is rejected rather than
            // silently resolved to one of the two values.
            if (fields.put(key, value) != null) {
                throw TransportException("duplicate object key $key")
            }
            skipWhitespace(text, cursor)
            if (cursor[0] >= text.length) throw TransportException("unterminated object")
            when (text[cursor[0]++]) {
                '}' -> return fields
                ',' -> continue
                else -> throw TransportException("expected ',' or '}' in object")
            }
        }
    }

    private fun readArray(text: String, cursor: IntArray): List<Any?> {
        cursor[0]++
        val items = mutableListOf<Any?>()
        skipWhitespace(text, cursor)
        if (cursor[0] < text.length && text[cursor[0]] == ']') {
            cursor[0]++
            return items
        }
        while (true) {
            items.add(readValue(text, cursor))
            skipWhitespace(text, cursor)
            if (cursor[0] >= text.length) throw TransportException("unterminated array")
            when (text[cursor[0]++]) {
                ']' -> return items
                ',' -> continue
                else -> throw TransportException("expected ',' or ']' in array")
            }
        }
    }

    private fun readString(text: String, cursor: IntArray): String {
        if (cursor[0] >= text.length || text[cursor[0]] != '"') {
            throw TransportException("expected a string")
        }
        cursor[0]++
        val out = StringBuilder()
        while (cursor[0] < text.length) {
            val character = text[cursor[0]++]
            if (character == '"') return out.toString()
            if (character != '\\') {
                out.append(character)
                continue
            }
            when (val escape = text[cursor[0]++]) {
                '"' -> out.append('"')
                '\\' -> out.append('\\')
                '/' -> out.append('/')
                'b' -> out.append('\b')
                'f' -> out.append('')
                'n' -> out.append('\n')
                'r' -> out.append('\r')
                't' -> out.append('\t')
                'u' -> {
                    out.append(text.substring(cursor[0], cursor[0] + 4).toInt(16).toChar())
                    cursor[0] += 4
                }
                else -> throw TransportException("unsupported escape \\$escape")
            }
        }
        throw TransportException("unterminated string")
    }

    private fun readNumber(text: String, cursor: IntArray): Any {
        val start = cursor[0]
        while (cursor[0] < text.length && text[cursor[0]] in "+-0123456789.eE") cursor[0]++
        val number = text.substring(start, cursor[0])
        return if (number.contains('.') || number.contains('e') || number.contains('E')) {
            number.toDoubleOrNull() ?: throw TransportException("invalid number $number")
        } else {
            number.toLongOrNull() ?: throw TransportException("invalid number $number")
        }
    }
}
