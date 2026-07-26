// A thin Java client for a local SESAME process.
//
// The client owns process lifecycle, NDJSON framing, and typed transport
// errors. Identity and authorization semantics remain in the SESAME
// executable. Dependencies: the JDK only, so the shim carries a small JSON
// reader and writer that handles the protocol's shapes and rejects the rest.

package ma.del.sesame;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public final class Sesame implements AutoCloseable {
    public static final String PROTOCOL_VERSION = "1";
    public static final int MAX_FRAME_BYTES = 1 << 20;

    /**
     * Bounds what a failing engine can make the caller hold: generous enough
     * for a refusal and its remedy, short of anything worth worrying about.
     */
    private static final int STARTUP_DIAGNOSTICS_BYTES = 4096;

    /** A stable error returned by the SESAME machine interface. */
    public static final class ProtocolException extends RuntimeException {
        public final String code;
        public final boolean retryable;

        ProtocolException(String code, String message, boolean retryable) {
            super("sesame protocol error " + code + ": " + message);
            this.code = code;
            this.retryable = retryable;
        }
    }

    /** A transport or framing failure. */
    public static final class TransportException extends RuntimeException {
        TransportException(String message) {
            super("sesame transport error: " + message);
        }
    }

    /**
     * A startup failure carrying what the engine said before it exited. The
     * message is already complete, so nothing is prefixed onto it.
     */
    public static final class StartupException extends RuntimeException {
        StartupException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Startup options for the local SESAME process. */
    public static final class Options {
        /** Empty means: SESAME_BINARY, then "sesame" on PATH. */
        public String binary = "";
        public String deployment;
        public String fyloBinary;
        public String fyloRoot;
        /**
         * Suppresses the protocol handshake the constructor performs. For
         * tests that deliberately drive a mismatched engine; production
         * callers leave it false.
         */
        public boolean skipCompatibilityCheck;
    }

    /**
     * A SESAME binary this client cannot speak to. It names both sides,
     * because the fix is always to change one of them.
     */
    public static final class IncompatibleEngineException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String clientProtocolVersion;
        public final String engineProtocolVersion;
        public final String engineVersion;
        public final List<String> missingOperations;

        IncompatibleEngineException(
                String clientProtocolVersion,
                String engineProtocolVersion,
                String engineVersion,
                List<String> missingOperations) {
            super(!engineProtocolVersion.equals(clientProtocolVersion)
                    ? "sesame engine " + engineVersion + " speaks machine protocol \""
                            + engineProtocolVersion + "\"; this client speaks \""
                            + clientProtocolVersion + "\""
                    : "sesame engine " + engineVersion + " does not support "
                            + missingOperations.size() + " operation(s) this client requires: "
                            + String.join(", ", missingOperations));
            this.clientProtocolVersion = clientProtocolVersion;
            this.engineProtocolVersion = engineProtocolVersion;
            this.engineVersion = engineVersion;
            this.missingOperations = missingOperations;
        }
    }

    private final Process process;
    private final BufferedWriter stdin;
    private final BufferedReader stdout;
    private long counter;
    private boolean closed;

    /** Resolves the engine path: explicit option, then SESAME_BINARY, then PATH. */
    private static String resolveBinary(String option) {
        if (option != null && !option.isEmpty()) {
            return option;
        }
        String fromEnvironment = System.getenv("SESAME_BINARY");
        return fromEnvironment == null || fromEnvironment.isEmpty() ? "sesame" : fromEnvironment;
    }

    public Sesame(Options options) {
        List<String> arguments = new ArrayList<>();
        // SESAME_BINARY names the engine when no option does; an explicit option still wins.
        arguments.add(resolveBinary(options.binary));
        arguments.add("exec");
        arguments.add("--loop");
        if (options.deployment != null && !options.deployment.isEmpty()) {
            arguments.add("--deployment");
            arguments.add(options.deployment);
        }
        if ((options.fyloBinary != null && !options.fyloBinary.isEmpty())
                || (options.fyloRoot != null && !options.fyloRoot.isEmpty())) {
            arguments.add("--fylo-binary");
            arguments.add(options.fyloBinary == null ? "" : options.fyloBinary);
            arguments.add("--fylo-root");
            arguments.add(options.fyloRoot == null ? "" : options.fyloRoot);
        }
        try {
            ProcessBuilder builder = new ProcessBuilder(arguments);
            // The engine reports a missing deployment or an unusable FYLO root
            // on stderr and then exits. Discarding that would leave the caller
            // with a dead process and no reason.
            this.process = builder.start();
        } catch (IOException error) {
            throw new TransportException("start sesame: " + error.getMessage());
        }
        this.stdin = new BufferedWriter(
                new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
        this.stdout = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));

        // A mismatched engine is found here rather than partway through a
        // security flow that then cannot finish. system.version needs no
        // storage, so this works before a FYLO root is configured.
        if (!options.skipCompatibilityCheck) {
            try {
                checkCompatibility();
            } catch (RuntimeException error) {
                String diagnostic = startupDiagnostics();
                close();
                if (!diagnostic.isEmpty()) {
                    // A TransportException prefixes its own message, so
                    // wrapping one in another would print the prefix twice.
                    throw new StartupException(error.getMessage() + ": " + diagnostic, error);
                }
                throw error;
            }
        }
        // The engine is up; an undrained stderr pipe would eventually block it.
        Thread drain = new Thread(() -> {
            try (InputStream diagnostics = process.getErrorStream()) {
                while (diagnostics.read() >= 0) {
                    // discard
                }
            } catch (IOException ignored) {
                // The child is gone; nothing left to drain.
            }
        });
        drain.setDaemon(true);
        drain.start();
    }

    /** Reads what a failing engine said before it exited. */
    private String startupDiagnostics() {
        try (InputStream diagnostics = process.getErrorStream()) {
            byte[] buffer = new byte[STARTUP_DIAGNOSTICS_BYTES];
            int read = diagnostics.read(buffer);
            return read <= 0 ? "" : new String(buffer, 0, read, StandardCharsets.UTF_8).trim();
        } catch (IOException error) {
            return "";
        }
    }

    /** Fails unless the engine speaks this client's machine protocol. */
    @SuppressWarnings("unchecked")
    public Object checkCompatibility() {
        Map<String, Object> version = (Map<String, Object>) version();
        String engine = String.valueOf(version.get("protocol_version"));
        if (!PROTOCOL_VERSION.equals(engine)) {
            throw new IncompatibleEngineException(
                    PROTOCOL_VERSION, engine, String.valueOf(version.get("version")), List.of());
        }
        return version;
    }

    /**
     * Fails unless the engine routes every named operation. Call it at startup
     * with what the application depends on: finding out here beats an
     * operation_not_found in the middle of a login.
     */
    @SuppressWarnings("unchecked")
    public Object requireOperations(String... operations) {
        Map<String, Object> version = (Map<String, Object>) version();
        Object reported = version.get("operations");
        List<Object> routed = reported instanceof List ? (List<Object>) reported : List.of();
        List<String> missing = new ArrayList<>();
        for (String operation : operations) {
            if (!routed.contains(operation)) {
                missing.add(operation);
            }
        }
        if (!missing.isEmpty()) {
            missing.sort(null);
            throw new IncompatibleEngineException(
                    PROTOCOL_VERSION,
                    String.valueOf(version.get("protocol_version")),
                    String.valueOf(version.get("version")),
                    missing);
        }
        return version;
    }

    /** Sends one operation and returns its result. */
    public Object request(String operation, Map<String, Object> parameters) {
        if (closed) {
            throw new TransportException("sesame client is closed");
        }
        counter++;
        String requestId = "java-" + System.nanoTime() + "-" + counter;
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("protocol_version", PROTOCOL_VERSION);
        envelope.put("request_id", requestId);
        envelope.put("operation", operation);
        envelope.put("parameters", parameters == null ? new LinkedHashMap<String, Object>() : parameters);

        String frame = Json.write(envelope);
        if (frame.getBytes(StandardCharsets.UTF_8).length > MAX_FRAME_BYTES) {
            throw new TransportException("request exceeds the maximum frame size");
        }
        try {
            stdin.write(frame);
            stdin.write('\n');
            stdin.flush();
            String line = stdout.readLine();
            if (line == null) {
                throw new TransportException("sesame process exited");
            }
            return decodeResponse(requestId, line);
        } catch (IOException error) {
            throw new TransportException(error.getMessage());
        }
    }

    private static Object decodeResponse(String requestId, String line) {
        Object parsed = Json.read(line);
        if (!(parsed instanceof Map)) {
            throw new TransportException("response is not a JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> response = (Map<String, Object>) parsed;
        if (!PROTOCOL_VERSION.equals(response.get("protocol_version"))) {
            throw new TransportException("unsupported protocol version");
        }
        if (!requestId.equals(response.get("request_id"))) {
            throw new TransportException("response request ID mismatch");
        }
        Object ok = response.get("ok");
        if (!(ok instanceof Boolean)) {
            throw new TransportException("response has no ok field");
        }
        if (!((Boolean) ok)) {
            Object rawError = response.get("error");
            if (!(rawError instanceof Map)) {
                throw new TransportException("failure response has no error");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> error = (Map<String, Object>) rawError;
            throw new ProtocolException(
                    String.valueOf(error.getOrDefault("code", "")),
                    String.valueOf(error.getOrDefault("message", "")),
                    Boolean.TRUE.equals(error.get("retryable")));
        }
        return response.get("result");
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            stdin.close();
            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (IOException | InterruptedException error) {
            process.destroyForcibly();
            if (error instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Builds a flat string parameter map. */
    public static Map<String, Object> parameters(String... pairs) {
        if (pairs.length % 2 != 0) {
            throw new IllegalArgumentException("parameters requires key/value pairs");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        for (int index = 0; index < pairs.length; index += 2) {
            map.put(pairs[index], pairs[index + 1]);
        }
        return map;
    }

    // System operations.
    public Object ping() {
        return request("system.ping", null);
    }

    public Object version() {
        return request("system.version", null);
    }

    public Object readiness() {
        return request("system.readiness", null);
    }

    public Object metrics() {
        return request("system.metrics", null);
    }

    // Tenants and principals.
    public Object tenantBootstrap(String name) {
        return request("tenant.bootstrap", parameters("name", name));
    }

    public Object tenantGetByName(String name) {
        return request("tenant.get", parameters("name", name));
    }

    public Object principalCreate(String tenantId, String kind, String namespace, String value) {
        return request("principal.create", parameters(
                "tenant_id", tenantId,
                "kind", kind,
                "identifier_namespace", namespace,
                "identifier_value", value));
    }

    public Object principalGetById(String principalId) {
        return request("principal.get", parameters("principal_id", principalId));
    }

    public Object principalSuspend(String principalId) {
        return request("principal.suspend", parameters("principal_id", principalId));
    }

    // Authorization.
    public Object roleCreate(String tenantId, String name, List<Map<String, Object>> permissions) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("name", name);
        map.put("permissions", permissions);
        return request("role.create", map);
    }

    public Object grantCreate(String tenantId, String principalId, String roleId) {
        return request("grant.create", parameters(
                "tenant_id", tenantId, "principal_id", principalId, "role_id", roleId));
    }

    public Object grantRevoke(String grantId) {
        return request("grant.revoke", parameters("grant_id", grantId));
    }

    // Asks the same question as decide, but proves a session instead of naming a principal.
    //
    // The engine verifies the session and derives context under the reserved
    // "session." prefix, so a caller cannot assert its own assurance level. That
    // is what makes a step-up condition worth trusting.
    public Object decideForSession(
            String tenantId,
            String sessionId,
            String sessionSecret,
            String action,
            String resource) {
        return request("authorize.decide", parameters(
                "tenant_id", tenantId,
                "session_id", sessionId,
                "session_secret", sessionSecret,
                "action", action,
                "resource", resource));
    }

    public Object decide(String tenantId, String principalId, String action, String resource) {
        return request("authorize.decide", parameters(
                "tenant_id", tenantId,
                "principal_id", principalId,
                "action", action,
                "resource", resource));
    }

    // Authentication.
    public Object setPassword(String principalId, String password) {
        return request("authenticator.set_password",
                parameters("principal_id", principalId, "password", password));
    }

    /**
     * Starts a login transaction. It succeeds whether or not the identifier
     * resolves, so the result never reveals which identifiers exist.
     */
    public Object authnBegin(String tenantId, String namespace, String value) {
        return request("authn.begin", parameters(
                "tenant_id", tenantId,
                "identifier_namespace", namespace,
                "identifier_value", value));
    }

    public Object authnVerifyPassword(String transactionId, String password) {
        return request("authn.verify_password",
                parameters("transaction_id", transactionId, "password", password));
    }

    public Object authnComplete(String transactionId, long lifetimeSeconds) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("transaction_id", transactionId);
        map.put("lifetime_seconds", lifetimeSeconds);
        return request("authn.complete", map);
    }

    public Object sessionVerify(String sessionId, String secret) {
        return request("session.verify",
                parameters("session_id", sessionId, "session_secret", secret));
    }

    public Object sessionRevoke(String sessionId, String reason) {
        return request("session.revoke",
                parameters("session_id", sessionId, "reason", reason));
    }


    // Groups and administration.
    public Object groupCreate(String tenantId, String name) {
        return request("group.create", parameters("tenant_id", tenantId, "name", name));
    }

    public Object groupMemberAdd(String groupId, String principalId) {
        return request("group.member_add",
                parameters("group_id", groupId, "principal_id", principalId));
    }

    public Object groupMemberRemove(String groupId, String principalId) {
        return request("group.member_remove",
                parameters("group_id", groupId, "principal_id", principalId));
    }

    public Object adminBootstrap(String tenantName, String namespace, String value) {
        return request("admin.bootstrap", parameters(
                "tenant_name", tenantName,
                "identifier_namespace", namespace,
                "identifier_value", value));
    }

    /** A batch always answers under one policy version. */
    public Object decideBatch(List<Map<String, Object>> requests) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("requests", requests);
        return request("authorize.decide_batch", map);
    }

    // Second factors. The TOTP shared secret is returned once at enrolment and
    // is never recoverable afterwards; a used code spends its time step
    // durably, so an observed code cannot be replayed inside its own window.
    public Object totpEnroll(String principalId, String issuer) {
        return request("authenticator.totp_enroll",
                parameters("principal_id", principalId, "issuer", issuer));
    }

    public Object totpActivate(String principalId, String code) {
        return request("authenticator.totp_activate",
                parameters("principal_id", principalId, "code", code));
    }

    public Object authnVerifyTotp(String transactionId, String code) {
        return request("authn.verify_totp",
                parameters("transaction_id", transactionId, "code", code));
    }

    /** Returns ten single-use codes once, retiring any previous set. */
    public Object recoveryCodesIssue(String principalId) {
        return request("authenticator.recovery_codes_issue",
                parameters("principal_id", principalId));
    }

    public Object authnVerifyRecoveryCode(String transactionId, String code) {
        return request("authn.verify_recovery_code",
                parameters("transaction_id", transactionId, "code", code));
    }

    // OIDC relying parties. An omitted audience is treated as third party, the
    // stricter rule: such a client needs recorded user consent before it
    // receives an authorization code.
    public Object oidcClientRegister(
            String tenantId,
            String name,
            String clientType,
            List<String> redirectUris,
            List<String> scopes,
            String audience,
            List<String> postLogoutRedirectUris) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("name", name);
        map.put("client_type", clientType);
        map.put("redirect_uris", redirectUris);
        map.put("scopes", scopes);
        map.put("audience", audience);
        map.put("post_logout_redirect_uris", postLogoutRedirectUris);
        return request("oidc_client.register", map);
    }

    public Object oidcClientGet(String clientId) {
        return request("oidc_client.get", parameters("client_id", clientId));
    }

    public Object oidcClientRotateSecret(String clientId) {
        return request("oidc_client.rotate_secret", parameters("client_id", clientId));
    }

    public Object oidcClientDisable(String clientId, String reason) {
        return request("oidc_client.disable",
                parameters("client_id", clientId, "reason", reason));
    }

    // The external interaction contract. authorize validates the whole request
    // before anything is shown to a user; the returned secret authorizes
    // completing that one interaction.
    public Object authorize(Map<String, Object> authorizationRequest) {
        return request("oidc.authorize", authorizationRequest);
    }

    public Object interactionGet(String interactionId) {
        return request("oidc.interaction_get", parameters("interaction_id", interactionId));
    }

    public Object interactionComplete(
            String interactionId, String interactionSecret, String sessionId, String sessionSecret) {
        return request("oidc.interaction_complete", parameters(
                "interaction_id", interactionId,
                "interaction_secret", interactionSecret,
                "session_id", sessionId,
                "session_secret", sessionSecret));
    }

    /**
     * A refresh response carries a new refresh token that replaces the one
     * presented; continuing to use the old one revokes the whole family.
     */
    // The device grant (RFC 8628). deviceAuthorize starts it; the person types
    // the user code elsewhere and approves or denies it there.
    public Object dpopVerify(String accessToken, String proof, String method, String uri) {
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("access_token", accessToken);
        parameters.put("dpop_proof", proof);
        parameters.put("http_method", method);
        parameters.put("http_uri", uri);
        return request("oidc.dpop_verify", parameters);
    }

    public Object pushedAuthorize(Map<String, Object> request) {
        return request("oidc.pushed_authorize", request);
    }

    public Object deviceAuthorize(String clientId, List<String> scopes) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("client_id", clientId);
        map.put("scopes", scopes == null ? List.of() : scopes);
        return request("oidc.device_authorize", map);
    }

    public Object deviceLookup(String tenantId, String userCode) {
        return request("oidc.device_lookup",
                parameters("tenant_id", tenantId, "user_code", userCode));
    }

    public Object deviceApprove(
            String tenantId, String userCode, String sessionId, String sessionSecret) {
        return request("oidc.device_approve", parameters(
                "tenant_id", tenantId,
                "user_code", userCode,
                "session_id", sessionId,
                "session_secret", sessionSecret));
    }

    public Object deviceDeny(String tenantId, String userCode) {
        return request("oidc.device_deny",
                parameters("tenant_id", tenantId, "user_code", userCode));
    }

    public Object tokenExchange(Map<String, Object> tokenRequest) {
        return request("oidc.token", tokenRequest);
    }

    public Object refreshFamilyRevoke(String familyId, String reason) {
        return request("oidc.refresh_family_revoke",
                parameters("family_id", familyId, "reason", reason));
    }

    public Object refreshFamilyGet(String familyId) {
        return request("oidc.refresh_family_get", parameters("family_id", familyId));
    }

    // Consent. The session proves who is agreeing, so a caller cannot consent
    // on somebody else's behalf. Withdrawing also revokes that client's refresh
    // families for the principal.
    public Object consentGrant(
            String sessionId, String sessionSecret, String clientId, List<String> scopes) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("session_id", sessionId);
        map.put("session_secret", sessionSecret);
        map.put("client_id", clientId);
        map.put("scopes", scopes);
        return request("oidc.consent_grant", map);
    }

    public Object consentWithdraw(String principalId, String clientId) {
        return request("oidc.consent_withdraw",
                parameters("principal_id", principalId, "client_id", clientId));
    }

    public Object consentGet(String principalId, String clientId) {
        return request("oidc.consent_get",
                parameters("principal_id", principalId, "client_id", clientId));
    }

    // Standards surfaces. Endpoint paths are the host's own; the engine
    // composes them under the configured issuer and refuses any that would
    // leave that origin.
    public Object standardsDispatch(Map<String, Object> request) {
        Map<String, Object> parameters = new LinkedHashMap<>(request);
        parameters.put("contract_version", "1");
        return this.request("standards.dispatch", parameters);
    }

    public Object discovery(Map<String, Object> endpoints) {
        return request("oidc.discovery", endpoints);
    }

    public Object signingKeys() {
        return request("token.jwks", new LinkedHashMap<>());
    }

    /**
     * Introspection reports live grant state, not just signature validity:
     * this is where a revoked session shows up.
     */
    public Object introspect(String clientId, String clientSecret, String token) {
        return request("oidc.introspect", parameters(
                "token", token, "client_id", clientId, "client_secret", clientSecret));
    }

    public Object revoke(String clientId, String clientSecret, String token) {
        return request("oidc.revoke", parameters(
                "token", token, "client_id", clientId, "client_secret", clientSecret));
    }

    /**
     * The hint is required and may be expired; revoking its session also ends
     * every refresh grant resting on it.
     */
    public Object logout(String idTokenHint, String postLogoutRedirectUri, String state) {
        return request("oidc.logout", parameters(
                "id_token_hint", idTokenHint,
                "post_logout_redirect_uri", postLogoutRedirectUri,
                "state", state));
    }

    // Passkeys. Binary values cross the protocol as base64. A user-verified
    // passkey establishes MFA on its own, with no prior factor.
    public Object passkeyRegisterBegin(String principalId) {
        return request("authenticator.passkey_register_begin",
                parameters("principal_id", principalId));
    }

    public Object passkeyRegisterFinish(
            String principalId, byte[] attestationObject, byte[] clientDataJson) {
        return request("authenticator.passkey_register_finish", parameters(
                "principal_id", principalId,
                "attestation_object", base64Url(attestationObject),
                "client_data_json", base64Url(clientDataJson)));
    }

    public Object passkeyList(String principalId) {
        return request("authenticator.passkey_list", parameters("principal_id", principalId));
    }

    public Object passkeyRemove(String credentialId) {
        return request("authenticator.passkey_remove", parameters("credential_id", credentialId));
    }

    public Object passkeyOptions(String transactionId) {
        return request("authn.passkey_options", parameters("transaction_id", transactionId));
    }

    public Object authnVerifyPasskey(
            String transactionId,
            String credentialId,
            byte[] authenticatorData,
            byte[] clientDataJson,
            byte[] signature) {
        return request("authn.verify_passkey", parameters(
                "transaction_id", transactionId,
                "credential_id", credentialId,
                "authenticator_data", base64Url(authenticatorData),
                "client_data_json", base64Url(clientDataJson),
                "signature", base64Url(signature)));
    }

    /** Encodes a binary WebAuthn value for transport, without padding. */
    // Inbound OIDC federation. The engine performs no network I/O: register and
    // configure return the exact URL the host must fetch, and every document
    // the host brings back is validated in the engine as untrusted input.
    // SCIM 2.0 provisioning. Every resource operation carries the bearer token,
    // so the engine always authenticates and a host cannot forget to.
    public Object provisioningClientRegister(
            String tenantId, String name, String identifierNamespace, boolean canManageGroups) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("name", name);
        map.put("identifier_namespace", identifierNamespace);
        map.put("can_manage_groups", canManageGroups);
        return request("scim.client_register", map);
    }

    public Object provisioningClientDisable(String tenantId, String scimClientId, String reason) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("scim_client_id", scimClientId);
        map.put("reason", reason);
        return request("scim.client_disable", map);
    }

    public Object provisioningClientRotateToken(String tenantId, String scimClientId) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("scim_client_id", scimClientId);
        return request("scim.client_rotate_token", map);
    }

    // SCIM Group provisioning. These require the client's can_manage_groups
    // grant: group membership drives authorization decisions.
    public Object scimGroupCreate(String token, String body) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("body", body);
        return request("scim.group_create", map);
    }

    public Object scimGroupGet(String token, String resourceId) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("resource_id", resourceId);
        return request("scim.group_get", map);
    }

    public Object scimGroupList(String token, String filter, long startIndex, long count) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("filter", filter);
        map.put("start_index", startIndex);
        map.put("count", count);
        return request("scim.group_list", map);
    }

    public Object scimGroupPatch(String token, String resourceId, String body) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("resource_id", resourceId);
        map.put("body", body);
        return request("scim.group_patch", map);
    }

    public Object scimGroupDeprovision(String token, String resourceId) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("resource_id", resourceId);
        return request("scim.group_deprovision", map);
    }

    public Object scimUserCreate(String token, String body) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("body", body);
        return request("scim.user_create", map);
    }

    public Object scimUserGet(String token, String resourceId) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("resource_id", resourceId);
        return request("scim.user_get", map);
    }

    public Object scimUserList(String token, String filter, long startIndex, long count) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("filter", filter);
        map.put("start_index", startIndex);
        map.put("count", count);
        return request("scim.user_list", map);
    }

    public Object scimUserPatch(String token, String resourceId, String body) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("resource_id", resourceId);
        map.put("body", body);
        return request("scim.user_patch", map);
    }

    public Object scimUserDeprovision(String token, String resourceId) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("token", token);
        map.put("resource_id", resourceId);
        return request("scim.user_deprovision", map);
    }

    public Object providerRegister(
            String tenantId,
            String name,
            String issuer,
            String clientId,
            String clientSecret,
            List<String> scopes,
            String subjectClaim,
            String emailClaim,
            String linking) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("name", name);
        map.put("issuer", issuer);
        map.put("client_id", clientId);
        map.put("client_secret", clientSecret);
        map.put("scopes", scopes);
        map.put("subject_claim", subjectClaim);
        map.put("email_claim", emailClaim);
        map.put("linking", linking);
        return request("federation.provider_register", map);
    }

    public Object samlProviderRegister(
            String tenantId,
            String name,
            String entityId,
            String ssoUrl,
            List<String> certificates,
            String identifierNamespace,
            String linking) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("name", name);
        map.put("entity_id", entityId);
        map.put("sso_url", ssoUrl);
        map.put("certificates", certificates);
        map.put("identifier_namespace", identifierNamespace);
        map.put("linking", linking);
        return request("saml.provider_register", map);
    }

    public Object samlProviderGet(String tenantId, String providerId) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("provider_id", providerId);
        return request("saml.provider_get", map);
    }

    public Object samlProviderDisable(String tenantId, String providerId, String reason) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("provider_id", providerId);
        map.put("reason", reason);
        return request("saml.provider_disable", map);
    }

    public Object samlLoginStart(String tenantId, String providerId, String consumerUrl) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("provider_id", providerId);
        map.put("consumer_url", consumerUrl);
        return request("saml.login_start", map);
    }

    public Object samlLoginComplete(String tenantId, String loginId, String assertion) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("login_id", loginId);
        map.put("assertion", assertion);
        return request("saml.login_complete", map);
    }

    public Object providerConfigure(
            String tenantId, String providerId, String discoveryDocument, String keySetDocument) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("provider_id", providerId);
        map.put("discovery_document", discoveryDocument);
        map.put("key_set_document", keySetDocument);
        return request("federation.provider_configure", map);
    }

    public Object providerDisable(String tenantId, String providerId, String reason) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("provider_id", providerId);
        map.put("reason", reason);
        return request("federation.provider_disable", map);
    }

    public Object providerGet(String tenantId, String providerId) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("provider_id", providerId);
        return request("federation.provider_get", map);
    }

    public Object federatedLoginStart(String tenantId, String providerId, String redirectUri) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("provider_id", providerId);
        map.put("redirect_uri", redirectUri);
        return request("federation.login_start", map);
    }

    public Object federatedLoginExchange(
            String tenantId, String loginId, String state, String code) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("login_id", loginId);
        map.put("state", state);
        map.put("code", code);
        return request("federation.login_exchange", map);
    }

    public Object federatedLoginComplete(String tenantId, String loginId, String idToken) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("tenant_id", tenantId);
        map.put("login_id", loginId);
        map.put("id_token", idToken);
        return request("federation.login_complete", map);
    }

    static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    /** A minimal JSON reader and writer for the protocol's shapes. */
    static final class Json {
        static String write(Object value) {
            StringBuilder out = new StringBuilder();
            writeValue(value, out);
            return out.toString();
        }

        private static void writeValue(Object value, StringBuilder out) {
            if (value == null) {
                out.append("null");
            } else if (value instanceof String) {
                writeString((String) value, out);
            } else if (value instanceof Boolean || value instanceof Integer
                    || value instanceof Long) {
                out.append(value);
            } else if (value instanceof Double || value instanceof Float) {
                double number = ((Number) value).doubleValue();
                if (number == Math.rint(number) && Math.abs(number) < 9.0e15) {
                    out.append((long) number);
                } else {
                    out.append(number);
                }
            } else if (value instanceof Map) {
                out.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    writeString(String.valueOf(entry.getKey()), out);
                    out.append(':');
                    writeValue(entry.getValue(), out);
                }
                out.append('}');
            } else if (value instanceof List) {
                out.append('[');
                boolean first = true;
                for (Object item : (List<?>) value) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    writeValue(item, out);
                }
                out.append(']');
            } else {
                throw new TransportException("unsupported JSON value " + value.getClass());
            }
        }

        private static void writeString(String text, StringBuilder out) {
            out.append('"');
            for (int index = 0; index < text.length(); index++) {
                char character = text.charAt(index);
                switch (character) {
                    case '"' -> out.append("\\\"");
                    case '\\' -> out.append("\\\\");
                    case '\n' -> out.append("\\n");
                    case '\r' -> out.append("\\r");
                    case '\t' -> out.append("\\t");
                    default -> {
                        if (character < 0x20) {
                            out.append(String.format("\\u%04x", (int) character));
                        } else {
                            out.append(character);
                        }
                    }
                }
            }
            out.append('"');
        }

        static Object read(String text) {
            int[] cursor = {0};
            Object value = readValue(text, cursor);
            skipWhitespace(text, cursor);
            if (cursor[0] != text.length()) {
                throw new TransportException("trailing content after JSON value");
            }
            return value;
        }

        private static void skipWhitespace(String text, int[] cursor) {
            while (cursor[0] < text.length() && Character.isWhitespace(text.charAt(cursor[0]))) {
                cursor[0]++;
            }
        }

        private static Object readValue(String text, int[] cursor) {
            skipWhitespace(text, cursor);
            if (cursor[0] >= text.length()) {
                throw new TransportException("unexpected end of JSON input");
            }
            char character = text.charAt(cursor[0]);
            return switch (character) {
                case '{' -> readObject(text, cursor);
                case '[' -> readArray(text, cursor);
                case '"' -> readString(text, cursor);
                case 't' -> readLiteral(text, cursor, "true", Boolean.TRUE);
                case 'f' -> readLiteral(text, cursor, "false", Boolean.FALSE);
                case 'n' -> readLiteral(text, cursor, "null", null);
                default -> readNumber(text, cursor);
            };
        }

        private static Object readLiteral(String text, int[] cursor, String literal, Object value) {
            if (!text.startsWith(literal, cursor[0])) {
                throw new TransportException("expected " + literal);
            }
            cursor[0] += literal.length();
            return value;
        }

        private static Map<String, Object> readObject(String text, int[] cursor) {
            cursor[0]++;
            Map<String, Object> fields = new LinkedHashMap<>();
            skipWhitespace(text, cursor);
            if (cursor[0] < text.length() && text.charAt(cursor[0]) == '}') {
                cursor[0]++;
                return fields;
            }
            while (true) {
                skipWhitespace(text, cursor);
                String key = readString(text, cursor);
                skipWhitespace(text, cursor);
                if (cursor[0] >= text.length() || text.charAt(cursor[0]) != ':') {
                    throw new TransportException("expected ':' in object");
                }
                cursor[0]++;
                Object value = readValue(text, cursor);
                // A duplicate key is ambiguous, so it is rejected rather than
                // silently resolved to one of the two values.
                if (fields.put(key, value) != null) {
                    throw new TransportException("duplicate object key " + key);
                }
                skipWhitespace(text, cursor);
                if (cursor[0] >= text.length()) {
                    throw new TransportException("unterminated object");
                }
                char next = text.charAt(cursor[0]++);
                if (next == '}') {
                    return fields;
                }
                if (next != ',') {
                    throw new TransportException("expected ',' or '}' in object");
                }
            }
        }

        private static List<Object> readArray(String text, int[] cursor) {
            cursor[0]++;
            List<Object> items = new ArrayList<>();
            skipWhitespace(text, cursor);
            if (cursor[0] < text.length() && text.charAt(cursor[0]) == ']') {
                cursor[0]++;
                return items;
            }
            while (true) {
                items.add(readValue(text, cursor));
                skipWhitespace(text, cursor);
                if (cursor[0] >= text.length()) {
                    throw new TransportException("unterminated array");
                }
                char next = text.charAt(cursor[0]++);
                if (next == ']') {
                    return items;
                }
                if (next != ',') {
                    throw new TransportException("expected ',' or ']' in array");
                }
            }
        }

        private static String readString(String text, int[] cursor) {
            if (cursor[0] >= text.length() || text.charAt(cursor[0]) != '"') {
                throw new TransportException("expected a string");
            }
            cursor[0]++;
            StringBuilder out = new StringBuilder();
            while (cursor[0] < text.length()) {
                char character = text.charAt(cursor[0]++);
                if (character == '"') {
                    return out.toString();
                }
                if (character != '\\') {
                    out.append(character);
                    continue;
                }
                char escape = text.charAt(cursor[0]++);
                switch (escape) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        out.append((char) Integer.parseInt(
                                text.substring(cursor[0], cursor[0] + 4), 16));
                        cursor[0] += 4;
                    }
                    default -> throw new TransportException("unsupported escape \\" + escape);
                }
            }
            throw new TransportException("unterminated string");
        }

        private static Object readNumber(String text, int[] cursor) {
            int start = cursor[0];
            while (cursor[0] < text.length()
                    && "+-0123456789.eE".indexOf(text.charAt(cursor[0])) >= 0) {
                cursor[0]++;
            }
            String number = text.substring(start, cursor[0]);
            try {
                if (number.contains(".") || number.contains("e") || number.contains("E")) {
                    return Double.parseDouble(number);
                }
                return Long.parseLong(number);
            } catch (NumberFormatException error) {
                throw new TransportException("invalid number " + number);
            }
        }
    }
}
