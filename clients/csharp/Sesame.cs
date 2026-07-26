// A thin C# client for a local SESAME process.
//
// The client owns process lifecycle, NDJSON framing, and typed transport
// errors. Identity and authorization semantics remain in the SESAME
// executable. Dependencies: the base class library only, using
// System.Text.Json for the protocol's shapes.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Sesame;

/// <summary>A stable error returned by the SESAME machine interface.</summary>
public sealed class ProtocolException : Exception
{
    public string Code { get; }
    public bool Retryable { get; }

    public ProtocolException(string code, string message, bool retryable)
        : base($"sesame protocol error {code}: {message}")
    {
        Code = code;
        Retryable = retryable;
    }
}

/// <summary>A transport or framing failure.</summary>
public sealed class TransportException : Exception
{
    public TransportException(string message) : base($"sesame transport error: {message}") { }
}

/// <summary>
/// A startup failure carrying what the engine said before it exited. The
/// message is already complete, so nothing is prefixed onto it.
/// </summary>
public sealed class StartupException : Exception
{
    public StartupException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Startup options for the local SESAME process.</summary>
public sealed class Options
{
    /// <summary>Empty means: SESAME_BINARY, then "sesame" on PATH.</summary>
    public string Binary { get; set; } = "";
    public string? Deployment { get; set; }
    public string? FyloBinary { get; set; }
    public string? FyloRoot { get; set; }

    /// <summary>
    /// Suppresses the protocol handshake the constructor performs. For tests
    /// that deliberately drive a mismatched engine; production callers leave
    /// it false.
    /// </summary>
    public bool SkipCompatibilityCheck { get; set; }
}

/// <summary>
/// A SESAME binary this client cannot speak to. It names both sides, because
/// the fix is always to change one of them.
/// </summary>
public sealed class IncompatibleEngineException : Exception
{
    public IncompatibleEngineException(
        string clientProtocolVersion,
        string engineProtocolVersion,
        string engineVersion,
        IReadOnlyList<string> missingOperations)
        : base(engineProtocolVersion != clientProtocolVersion
            ? $"sesame engine {engineVersion} speaks machine protocol "
                + $"\"{engineProtocolVersion}\"; this client speaks \"{clientProtocolVersion}\""
            : $"sesame engine {engineVersion} does not support {missingOperations.Count} "
                + $"operation(s) this client requires: {string.Join(", ", missingOperations)}")
    {
        ClientProtocolVersion = clientProtocolVersion;
        EngineProtocolVersion = engineProtocolVersion;
        EngineVersion = engineVersion;
        MissingOperations = missingOperations;
    }

    public string ClientProtocolVersion { get; }
    public string EngineProtocolVersion { get; }
    public string EngineVersion { get; }
    public IReadOnlyList<string> MissingOperations { get; }
}

/// <summary>Owns one long-lived local SESAME subprocess.</summary>
public sealed class Client : IDisposable
{
    public const string ProtocolVersion = "1";
    public const int MaxFrameBytes = 1 << 20;

    private readonly Process _process;
    private long _counter;
    private bool _closed;

    /// <summary>
    /// Resolves the engine path: explicit option, then SESAME_BINARY, then PATH.
    /// </summary>
    private static string ResolveBinary(string? option) =>
        !string.IsNullOrEmpty(option) ? option
            : Environment.GetEnvironmentVariable("SESAME_BINARY") is { Length: > 0 } fromEnvironment
                ? fromEnvironment
                : "sesame";

    /// <summary>
    /// Bounds what a failing engine can make the caller hold: generous enough
    /// for a refusal and its remedy, short of anything worth worrying about.
    /// </summary>
    private const int StartupDiagnosticsBytes = 4096;

    /// <summary>How long to let a dying engine finish writing its reason.</summary>
    private const int StartupDiagnosticsWaitMs = 500;

    public Client(Options options)
    {
        var info = new ProcessStartInfo
        {
            // SESAME_BINARY names the engine when no option does; an explicit option still wins.
            FileName = ResolveBinary(options.Binary),
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = new UTF8Encoding(false),
        };
        info.ArgumentList.Add("exec");
        info.ArgumentList.Add("--loop");
        if (!string.IsNullOrEmpty(options.Deployment))
        {
            info.ArgumentList.Add("--deployment");
            info.ArgumentList.Add(options.Deployment);
        }
        if (!string.IsNullOrEmpty(options.FyloBinary) || !string.IsNullOrEmpty(options.FyloRoot))
        {
            info.ArgumentList.Add("--fylo-binary");
            info.ArgumentList.Add(options.FyloBinary ?? "");
            info.ArgumentList.Add("--fylo-root");
            info.ArgumentList.Add(options.FyloRoot ?? "");
        }

        var process = Process.Start(info) ?? throw new TransportException("start sesame");
        _process = process;

        // A mismatched engine is found here rather than partway through a
        // security flow that then cannot finish. system.version needs no
        // storage, so this works before a FYLO root is configured.
        if (!options.SkipCompatibilityCheck)
        {
            try
            {
                CheckCompatibility();
            }
            catch (Exception error)
            {
                // The engine reports a missing deployment or an unusable FYLO
                // root on stderr and then exits. Without this the caller sees
                // a dead process and no reason.
                var diagnostic = StartupDiagnostics();
                Dispose();
                if (diagnostic.Length > 0)
                {
                    // A TransportException prefixes its own message, so
                    // wrapping one in another would print the prefix twice.
                    throw new StartupException($"{error.Message}: {diagnostic}", error);
                }
                throw;
            }
        }
        // The engine is up; an undrained stderr pipe would eventually block it.
        _ = process.StandardError.ReadToEndAsync();
    }

    /// <summary>Reads what a failing engine said before it exited.</summary>
    private string StartupDiagnostics()
    {
        try
        {
            // A broken pipe is reported before the child's last write has
            // necessarily been delivered. Give the process a moment to finish
            // exiting; if it has not, read only what is already buffered so a
            // live-but-incompatible engine cannot block startup forever.
            if (_process.WaitForExit(StartupDiagnosticsWaitMs))
            {
                var all = _process.StandardError.ReadToEnd();
                return all.Length <= StartupDiagnosticsBytes
                    ? all.Trim()
                    : all[..StartupDiagnosticsBytes].Trim();
            }
            var buffer = new char[StartupDiagnosticsBytes];
            var read = _process.StandardError.Read(buffer, 0, buffer.Length);
            return read <= 0 ? "" : new string(buffer, 0, read).Trim();
        }
        catch (Exception)
        {
            return "";
        }
    }

    /// <summary>Sends one operation and returns its result.</summary>
    public JsonElement Request(string operation, IDictionary<string, object?>? parameters = null)
    {
        if (_closed)
        {
            throw new TransportException("sesame client is closed");
        }
        _counter++;
        var requestId = $"cs-{DateTime.UtcNow.Ticks}-{_counter}";
        var envelope = new Dictionary<string, object?>
        {
            ["protocol_version"] = ProtocolVersion,
            ["request_id"] = requestId,
            ["operation"] = operation,
            ["parameters"] = parameters ?? new Dictionary<string, object?>(),
        };

        var frame = JsonSerializer.Serialize(envelope);
        if (Encoding.UTF8.GetByteCount(frame) > MaxFrameBytes)
        {
            throw new TransportException("request exceeds the maximum frame size");
        }

        _process.StandardInput.Write(frame);
        _process.StandardInput.Write('\n');
        _process.StandardInput.Flush();

        var line = _process.StandardOutput.ReadLine()
            ?? throw new TransportException("sesame process exited");
        return DecodeResponse(requestId, line);
    }

    private static JsonElement DecodeResponse(string requestId, string line)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(line);
        }
        catch (JsonException error)
        {
            throw new TransportException($"decode: {error.Message}");
        }
        var response = document.RootElement;
        if (!response.TryGetProperty("protocol_version", out var version)
            || version.GetString() != ProtocolVersion)
        {
            throw new TransportException("unsupported protocol version");
        }
        if (!response.TryGetProperty("request_id", out var id) || id.GetString() != requestId)
        {
            throw new TransportException("response request ID mismatch");
        }
        if (!response.TryGetProperty("ok", out var ok))
        {
            throw new TransportException("response has no ok field");
        }
        if (!ok.GetBoolean())
        {
            if (!response.TryGetProperty("error", out var error))
            {
                throw new TransportException("failure response has no error");
            }
            throw new ProtocolException(
                error.TryGetProperty("code", out var code) ? code.GetString() ?? "" : "",
                error.TryGetProperty("message", out var message) ? message.GetString() ?? "" : "",
                error.TryGetProperty("retryable", out var retryable) && retryable.GetBoolean());
        }
        return response.TryGetProperty("result", out var result) ? result.Clone() : default;
    }

    public void Dispose()
    {
        if (_closed)
        {
            return;
        }
        _closed = true;
        try
        {
            _process.StandardInput.Close();
            if (!_process.WaitForExit(2000))
            {
                _process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception error) when (error is InvalidOperationException or IOException)
        {
            // The child already exited: closing its stdin reports either a
            // broken pipe or an invalid operation depending on how far the
            // teardown got. Letting either escape would replace the real
            // failure — the reason the engine refused to start — with a
            // message about the pipe used to tell it so.
        }
        _process.Dispose();
    }

    private static Dictionary<string, object?> Parameters(params string[] pairs)
    {
        if (pairs.Length % 2 != 0)
        {
            throw new ArgumentException("parameters requires key/value pairs", nameof(pairs));
        }
        var map = new Dictionary<string, object?>();
        for (var index = 0; index < pairs.Length; index += 2)
        {
            map[pairs[index]] = pairs[index + 1];
        }
        return map;
    }

    // System operations.
    public JsonElement Ping() => Request("system.ping");
    public JsonElement Version() => Request("system.version");
    public JsonElement Readiness() => Request("system.readiness");
    public JsonElement Metrics() => Request("system.metrics");

    // Tenants and principals.
    public JsonElement TenantBootstrap(string name) =>
        Request("tenant.bootstrap", Parameters("name", name));

    public JsonElement TenantGetByName(string name) =>
        Request("tenant.get", Parameters("name", name));

    public JsonElement PrincipalCreate(string tenantId, string kind, string ns, string value) =>
        Request("principal.create", Parameters(
            "tenant_id", tenantId, "kind", kind,
            "identifier_namespace", ns, "identifier_value", value));

    public JsonElement PrincipalGetById(string principalId) =>
        Request("principal.get", Parameters("principal_id", principalId));

    public JsonElement PrincipalSuspend(string principalId) =>
        Request("principal.suspend", Parameters("principal_id", principalId));

    // Authorization.
    public JsonElement RoleCreate(
        string tenantId, string name, IEnumerable<IDictionary<string, object?>> permissions) =>
        Request("role.create", new Dictionary<string, object?>
        {
            ["tenant_id"] = tenantId,
            ["name"] = name,
            ["permissions"] = permissions,
        });

    public JsonElement GrantCreate(string tenantId, string principalId, string roleId) =>
        Request("grant.create", Parameters(
            "tenant_id", tenantId, "principal_id", principalId, "role_id", roleId));

    public JsonElement GrantRevoke(string grantId) =>
        Request("grant.revoke", Parameters("grant_id", grantId));

    // Asks the same question as decide, but proves a session instead of naming a principal.
    //
    // The engine verifies the session and derives context under the reserved
    // "session." prefix, so a caller cannot assert its own assurance level. That
    // is what makes a step-up condition worth trusting.
    public JsonElement DecideForSession(
        string tenantId,
        string sessionId,
        string sessionSecret,
        string action,
        string resource) =>
        Request("authorize.decide", Parameters(
            "tenant_id", tenantId,
            "session_id", sessionId,
            "session_secret", sessionSecret,
            "action", action,
            "resource", resource));

    public JsonElement Decide(string tenantId, string principalId, string action, string resource) =>
        Request("authorize.decide", Parameters(
            "tenant_id", tenantId, "principal_id", principalId,
            "action", action, "resource", resource));

    // Authentication.
    public JsonElement SetPassword(string principalId, string password) =>
        Request("authenticator.set_password",
            Parameters("principal_id", principalId, "password", password));

    /// <summary>
    /// Starts a login transaction. It succeeds whether or not the identifier
    /// resolves, so the result never reveals which identifiers exist.
    /// </summary>
    public JsonElement AuthnBegin(string tenantId, string ns, string value) =>
        Request("authn.begin", Parameters(
            "tenant_id", tenantId, "identifier_namespace", ns, "identifier_value", value));

    public JsonElement AuthnVerifyPassword(string transactionId, string password) =>
        Request("authn.verify_password",
            Parameters("transaction_id", transactionId, "password", password));

    public JsonElement AuthnComplete(string transactionId, long lifetimeSeconds = 0) =>
        Request("authn.complete", new Dictionary<string, object?>
        {
            ["transaction_id"] = transactionId,
            ["lifetime_seconds"] = lifetimeSeconds,
        });

    public JsonElement SessionVerify(string sessionId, string secret) =>
        Request("session.verify",
            Parameters("session_id", sessionId, "session_secret", secret));

    /// <summary>Fails unless the engine speaks this client's machine protocol.</summary>
    public JsonElement CheckCompatibility()
    {
        var version = Version();
        var engine = version.TryGetProperty("protocol_version", out var value)
            ? value.GetString() ?? ""
            : "";
        if (engine != ProtocolVersion)
        {
            throw new IncompatibleEngineException(
                ProtocolVersion, engine, EngineVersionOf(version), Array.Empty<string>());
        }
        return version;
    }

    /// <summary>
    /// Fails unless the engine routes every named operation. Call it at
    /// startup with what the application depends on: finding out here beats an
    /// operation_not_found in the middle of a login.
    /// </summary>
    public JsonElement RequireOperations(params string[] operations)
    {
        var version = Version();
        var routed = new HashSet<string>(StringComparer.Ordinal);
        if (version.TryGetProperty("operations", out var reported)
            && reported.ValueKind == JsonValueKind.Array)
        {
            foreach (var operation in reported.EnumerateArray())
            {
                var name = operation.GetString();
                if (name is not null)
                {
                    routed.Add(name);
                }
            }
        }
        var missing = operations.Where(operation => !routed.Contains(operation))
            .OrderBy(operation => operation, StringComparer.Ordinal).ToArray();
        if (missing.Length > 0)
        {
            throw new IncompatibleEngineException(
                ProtocolVersion,
                version.TryGetProperty("protocol_version", out var engine) ? engine.GetString() ?? "" : "",
                EngineVersionOf(version),
                missing);
        }
        return version;
    }

    private static string EngineVersionOf(JsonElement version) =>
        version.TryGetProperty("version", out var value) ? value.GetString() ?? "" : "";

    public JsonElement SessionRevoke(string sessionId, string reason = "") =>
        Request("session.revoke", Parameters("session_id", sessionId, "reason", reason));

    // Groups and administration.
    public JsonElement GroupCreate(string tenantId, string name) =>
        Request("group.create", Parameters("tenant_id", tenantId, "name", name));

    public JsonElement GroupMemberAdd(string groupId, string principalId) =>
        Request("group.member_add", Parameters("group_id", groupId, "principal_id", principalId));

    public JsonElement GroupMemberRemove(string groupId, string principalId) =>
        Request("group.member_remove", Parameters("group_id", groupId, "principal_id", principalId));

    public JsonElement AdminBootstrap(string tenantName, string ns, string value) =>
        Request("admin.bootstrap", Parameters(
            "tenant_name", tenantName, "identifier_namespace", ns, "identifier_value", value));

    /// <summary>A batch always answers under one policy version.</summary>
    public JsonElement DecideBatch(IEnumerable<IDictionary<string, object?>> requests) =>
        Request("authorize.decide_batch", new Dictionary<string, object?>
        {
            ["requests"] = requests,
        });

    // Second factors. The TOTP shared secret is returned once at enrolment and
    // is never recoverable afterwards; a used code spends its time step
    // durably, so an observed code cannot be replayed inside its own window.
    public JsonElement TotpEnroll(string principalId, string issuer = "SESAME") =>
        Request("authenticator.totp_enroll", Parameters("principal_id", principalId, "issuer", issuer));

    public JsonElement TotpActivate(string principalId, string code) =>
        Request("authenticator.totp_activate", Parameters("principal_id", principalId, "code", code));

    public JsonElement AuthnVerifyTotp(string transactionId, string code) =>
        Request("authn.verify_totp", Parameters("transaction_id", transactionId, "code", code));

    /// <summary>Returns ten single-use codes once, retiring any previous set.</summary>
    public JsonElement RecoveryCodesIssue(string principalId) =>
        Request("authenticator.recovery_codes_issue", Parameters("principal_id", principalId));

    public JsonElement AuthnVerifyRecoveryCode(string transactionId, string code) =>
        Request("authn.verify_recovery_code", Parameters("transaction_id", transactionId, "code", code));

    // OIDC relying parties. An omitted audience is treated as third party, the
    // stricter rule: such a client needs recorded user consent before it
    // receives an authorization code.
    public JsonElement OidcClientRegister(
        string tenantId,
        string name,
        string clientType,
        IEnumerable<string> redirectUris,
        IEnumerable<string>? scopes = null,
        string audience = "",
        IEnumerable<string>? postLogoutRedirectUris = null) =>
        Request("oidc_client.register", new Dictionary<string, object?>
        {
            ["tenant_id"] = tenantId,
            ["name"] = name,
            ["client_type"] = clientType,
            ["redirect_uris"] = redirectUris,
            ["scopes"] = scopes ?? Array.Empty<string>(),
            ["audience"] = audience,
            ["post_logout_redirect_uris"] = postLogoutRedirectUris ?? Array.Empty<string>(),
        });

    public JsonElement OidcClientGet(string clientId) =>
        Request("oidc_client.get", Parameters("client_id", clientId));

    public JsonElement OidcClientRotateSecret(string clientId) =>
        Request("oidc_client.rotate_secret", Parameters("client_id", clientId));

    public JsonElement OidcClientDisable(string clientId, string reason = "") =>
        Request("oidc_client.disable", Parameters("client_id", clientId, "reason", reason));

    // The external interaction contract. Authorize validates the whole request
    // before anything is shown to a user; the returned secret authorizes
    // completing that one interaction.
    public JsonElement Authorize(IDictionary<string, object?> authorizationRequest) =>
        Request("oidc.authorize", authorizationRequest);

    public JsonElement InteractionGet(string interactionId) =>
        Request("oidc.interaction_get", Parameters("interaction_id", interactionId));

    public JsonElement InteractionComplete(
        string interactionId, string interactionSecret, string sessionId, string sessionSecret) =>
        Request("oidc.interaction_complete", Parameters(
            "interaction_id", interactionId,
            "interaction_secret", interactionSecret,
            "session_id", sessionId,
            "session_secret", sessionSecret));

    /// <summary>
    /// A refresh response carries a new refresh token that replaces the one
    /// presented; continuing to use the old one revokes the whole family.
    /// </summary>
    // The device grant (RFC 8628). DeviceAuthorize starts it; the person types
    // the user code elsewhere and approves or denies it there.
    public JsonElement DPoPVerify(string accessToken, string proof, string method, string uri) =>
        Request("oidc.dpop_verify", new Dictionary<string, object?>
        {
            ["access_token"] = accessToken,
            ["dpop_proof"] = proof,
            ["http_method"] = method,
            ["http_uri"] = uri,
        });

    public JsonElement PushedAuthorize(IDictionary<string, object?> request) =>
        Request("oidc.pushed_authorize", request);

    public JsonElement DeviceAuthorize(string clientId, IEnumerable<string>? scopes = null) =>
        Request("oidc.device_authorize", new Dictionary<string, object?>
        {
            ["client_id"] = clientId,
            ["scopes"] = scopes ?? Array.Empty<string>()
        });

    public JsonElement DeviceLookup(string tenantId, string userCode) =>
        Request("oidc.device_lookup", Parameters("tenant_id", tenantId, "user_code", userCode));

    public JsonElement DeviceApprove(
        string tenantId, string userCode, string sessionId, string sessionSecret) =>
        Request("oidc.device_approve", Parameters(
            "tenant_id", tenantId, "user_code", userCode,
            "session_id", sessionId, "session_secret", sessionSecret));

    public JsonElement DeviceDeny(string tenantId, string userCode) =>
        Request("oidc.device_deny", Parameters("tenant_id", tenantId, "user_code", userCode));

    public JsonElement TokenExchange(IDictionary<string, object?> tokenRequest) =>
        Request("oidc.token", tokenRequest);

    public JsonElement RefreshFamilyRevoke(string familyId, string reason = "") =>
        Request("oidc.refresh_family_revoke", Parameters("family_id", familyId, "reason", reason));

    public JsonElement RefreshFamilyGet(string familyId) =>
        Request("oidc.refresh_family_get", Parameters("family_id", familyId));

    // Consent. The session proves who is agreeing, so a caller cannot consent
    // on somebody else's behalf. Withdrawing also revokes that client's refresh
    // families for the principal.
    public JsonElement ConsentGrant(
        string sessionId, string sessionSecret, string clientId, IEnumerable<string> scopes) =>
        Request("oidc.consent_grant", new Dictionary<string, object?>
        {
            ["session_id"] = sessionId,
            ["session_secret"] = sessionSecret,
            ["client_id"] = clientId,
            ["scopes"] = scopes,
        });

    public JsonElement ConsentWithdraw(string principalId, string clientId) =>
        Request("oidc.consent_withdraw", Parameters("principal_id", principalId, "client_id", clientId));

    public JsonElement ConsentGet(string principalId, string clientId) =>
        Request("oidc.consent_get", Parameters("principal_id", principalId, "client_id", clientId));

    // Standards surfaces. Endpoint paths are the host's own; the engine
    // composes them under the configured issuer and refuses any that would
    // leave that origin.
    public JsonElement Discovery(IDictionary<string, object?>? endpoints = null) =>
        Request("oidc.discovery", endpoints ?? new Dictionary<string, object?>());

    public JsonElement SigningKeys() => Request("token.jwks");

    /// <summary>
    /// Introspection reports live grant state, not just signature validity:
    /// this is where a revoked session shows up.
    /// </summary>
    public JsonElement Introspect(string clientId, string clientSecret, string token) =>
        Request("oidc.introspect", Parameters(
            "token", token, "client_id", clientId, "client_secret", clientSecret));

    public JsonElement Revoke(string clientId, string clientSecret, string token) =>
        Request("oidc.revoke", Parameters(
            "token", token, "client_id", clientId, "client_secret", clientSecret));

    /// <summary>
    /// The hint is required and may be expired; revoking its session also ends
    /// every refresh grant resting on it.
    /// </summary>
    public JsonElement Logout(string idTokenHint, string postLogoutRedirectUri = "", string state = "") =>
        Request("oidc.logout", Parameters(
            "id_token_hint", idTokenHint,
            "post_logout_redirect_uri", postLogoutRedirectUri,
            "state", state));

    // Passkeys. Binary values cross the protocol as base64. A user-verified
    // passkey establishes MFA on its own, with no prior factor.
    public JsonElement PasskeyRegisterBegin(string principalId) =>
        Request("authenticator.passkey_register_begin", Parameters("principal_id", principalId));

    public JsonElement PasskeyRegisterFinish(
        string principalId, byte[] attestationObject, byte[] clientDataJson) =>
        Request("authenticator.passkey_register_finish", Parameters(
            "principal_id", principalId,
            "attestation_object", Base64Url(attestationObject),
            "client_data_json", Base64Url(clientDataJson)));

    public JsonElement PasskeyList(string principalId) =>
        Request("authenticator.passkey_list", Parameters("principal_id", principalId));

    public JsonElement PasskeyRemove(string credentialId) =>
        Request("authenticator.passkey_remove", Parameters("credential_id", credentialId));

    public JsonElement PasskeyOptions(string transactionId) =>
        Request("authn.passkey_options", Parameters("transaction_id", transactionId));

    public JsonElement AuthnVerifyPasskey(
        string transactionId,
        string credentialId,
        byte[] authenticatorData,
        byte[] clientDataJson,
        byte[] signature) =>
        Request("authn.verify_passkey", Parameters(
            "transaction_id", transactionId,
            "credential_id", credentialId,
            "authenticator_data", Base64Url(authenticatorData),
            "client_data_json", Base64Url(clientDataJson),
            "signature", Base64Url(signature)));

    // Inbound OIDC federation. The engine performs no network I/O: register and
    // configure return the exact URL the host must fetch, and every document
    // the host brings back is validated in the engine as untrusted input.
    // SCIM 2.0 provisioning. Every resource operation carries the bearer token,
    // so the engine always authenticates and a host cannot forget to.
    public JsonElement ProvisioningClientRegister(
        string tenantId, string name, string identifierNamespace = "",
        bool canManageGroups = false) =>
        Request("scim.client_register", new Dictionary<string, object?>
        {
            ["tenant_id"] = tenantId,
            ["name"] = name,
            ["identifier_namespace"] = identifierNamespace,
            ["can_manage_groups"] = canManageGroups
        });

    public JsonElement ProvisioningClientDisable(
        string tenantId, string scimClientId, string reason = "") =>
        Request("scim.client_disable", Parameters(
            "tenant_id", tenantId, "scim_client_id", scimClientId, "reason", reason));

    public JsonElement ProvisioningClientRotateToken(string tenantId, string scimClientId) =>
        Request("scim.client_rotate_token", Parameters(
            "tenant_id", tenantId, "scim_client_id", scimClientId));

    // SCIM Group provisioning. These require the client's can_manage_groups
    // grant: group membership drives authorization decisions.
    public JsonElement SCIMGroupCreate(string token, string body) =>
        Request("scim.group_create", Parameters("token", token, "body", body));

    public JsonElement SCIMGroupGet(string token, string resourceId) =>
        Request("scim.group_get", Parameters("token", token, "resource_id", resourceId));

    public JsonElement SCIMGroupList(
        string token, string filter = "", long startIndex = 1, long count = 0) =>
        Request("scim.group_list", new Dictionary<string, object?>
        {
            ["token"] = token,
            ["filter"] = filter,
            ["start_index"] = startIndex,
            ["count"] = count
        });

    public JsonElement SCIMGroupPatch(string token, string resourceId, string body) =>
        Request("scim.group_patch", Parameters(
            "token", token, "resource_id", resourceId, "body", body));

    public JsonElement SCIMGroupDeprovision(string token, string resourceId) =>
        Request("scim.group_deprovision", Parameters(
            "token", token, "resource_id", resourceId));

    public JsonElement SCIMUserCreate(string token, string body) =>
        Request("scim.user_create", Parameters("token", token, "body", body));

    public JsonElement SCIMUserGet(string token, string resourceId) =>
        Request("scim.user_get", Parameters("token", token, "resource_id", resourceId));

    public JsonElement SCIMUserList(
        string token, string filter = "", long startIndex = 1, long count = 0) =>
        Request("scim.user_list", new Dictionary<string, object?>
        {
            ["token"] = token,
            ["filter"] = filter,
            ["start_index"] = startIndex,
            ["count"] = count
        });

    public JsonElement SCIMUserPatch(string token, string resourceId, string body) =>
        Request("scim.user_patch", Parameters(
            "token", token, "resource_id", resourceId, "body", body));

    public JsonElement SCIMUserDeprovision(string token, string resourceId) =>
        Request("scim.user_deprovision", Parameters(
            "token", token, "resource_id", resourceId));

    public JsonElement ProviderRegister(
        string tenantId,
        string name,
        string issuer,
        string clientId,
        string clientSecret,
        IEnumerable<string> scopes,
        string subjectClaim = "sub",
        string emailClaim = "",
        string linking = "strict") =>
        Request("federation.provider_register", new Dictionary<string, object?>
        {
            ["tenant_id"] = tenantId,
            ["name"] = name,
            ["issuer"] = issuer,
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["scopes"] = scopes,
            ["subject_claim"] = subjectClaim,
            ["email_claim"] = emailClaim,
            ["linking"] = linking
        });

    public JsonElement SAMLProviderRegister(
        string tenantId,
        string name,
        string entityId,
        string ssoUrl,
        string[] certificates,
        string identifierNamespace = "email",
        string linking = "strict") =>
        Request("saml.provider_register", new Dictionary<string, object?>
        {
            ["tenant_id"] = tenantId,
            ["name"] = name,
            ["entity_id"] = entityId,
            ["sso_url"] = ssoUrl,
            ["certificates"] = certificates,
            ["identifier_namespace"] = identifierNamespace,
            ["linking"] = linking
        });

    public JsonElement SAMLProviderGet(string tenantId, string providerId) =>
        Request("saml.provider_get", Parameters("tenant_id", tenantId, "provider_id", providerId));

    public JsonElement SAMLProviderDisable(string tenantId, string providerId, string reason = "") =>
        Request("saml.provider_disable", Parameters(
            "tenant_id", tenantId, "provider_id", providerId, "reason", reason));

    public JsonElement SAMLLoginStart(string tenantId, string providerId, string consumerUrl) =>
        Request("saml.login_start", Parameters(
            "tenant_id", tenantId, "provider_id", providerId, "consumer_url", consumerUrl));

    public JsonElement SAMLLoginComplete(string tenantId, string loginId, string assertion) =>
        Request("saml.login_complete", Parameters(
            "tenant_id", tenantId, "login_id", loginId, "assertion", assertion));

    public JsonElement ProviderConfigure(
        string tenantId, string providerId, string discoveryDocument, string keySetDocument) =>
        Request("federation.provider_configure", new Dictionary<string, object?>
        {
            ["tenant_id"] = tenantId,
            ["provider_id"] = providerId,
            ["discovery_document"] = discoveryDocument,
            ["key_set_document"] = keySetDocument
        });

    public JsonElement ProviderDisable(string tenantId, string providerId, string reason = "") =>
        Request("federation.provider_disable", Parameters(
            "tenant_id", tenantId, "provider_id", providerId, "reason", reason));

    public JsonElement ProviderGet(string tenantId, string providerId) =>
        Request("federation.provider_get", Parameters(
            "tenant_id", tenantId, "provider_id", providerId));

    public JsonElement FederatedLoginStart(
        string tenantId, string providerId, string redirectUri) =>
        Request("federation.login_start", Parameters(
            "tenant_id", tenantId, "provider_id", providerId, "redirect_uri", redirectUri));

    public JsonElement FederatedLoginExchange(
        string tenantId, string loginId, string state, string code) =>
        Request("federation.login_exchange", Parameters(
            "tenant_id", tenantId, "login_id", loginId, "state", state, "code", code));

    public JsonElement FederatedLoginComplete(
        string tenantId, string loginId, string idToken) =>
        Request("federation.login_complete", Parameters(
            "tenant_id", tenantId, "login_id", loginId, "id_token", idToken));

    /// <summary>Encodes a binary WebAuthn value for transport, without padding.</summary>
    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
