// Runs the shared SDK contract scenario against real compiled binaries.
//
// Every SESAME SDK drives this same sequence, so a divergence in any one
// client fails its own suite rather than hiding behind a mock. The harness is
// plain BCL: a test framework would contradict the shim's dependency-free
// promise.

using System.Diagnostics;
using System.Text.Json;
using Sesame;

var checks = 0;

void AreEqual(object? expected, object? actual, string what)
{
    checks++;
    if (!Equals(expected?.ToString(), actual?.ToString()))
    {
        throw new Exception($"{what}: expected {expected ?? "null"}, got {actual ?? "null"}");
    }
}

string? Field(JsonElement value, string key) =>
    value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var found)
        ? found.ValueKind switch
        {
            JsonValueKind.String => found.GetString(),
            JsonValueKind.Null => null,
            _ => found.ToString(),
        }
        : null;

JsonElement Object(JsonElement value, string key) => value.GetProperty(key);

string CodeOf(Action action)
{
    try
    {
        action();
    }
    catch (ProtocolException error)
    {
        return error.Code;
    }
    throw new Exception("expected a protocol error");
}

string RepositoryRoot()
{
    var candidate = new DirectoryInfo(Directory.GetCurrentDirectory());
    while (candidate is not null)
    {
        if (File.Exists(Path.Combine(candidate.FullName, "go.mod")))
        {
            return candidate.FullName;
        }
        candidate = candidate.Parent;
    }
    throw new Exception("could not locate the repository root");
}

string Build(string root, string workspace, string name, string source)
{
    var output = Path.Combine(workspace, name);
    var info = new ProcessStartInfo("go") { WorkingDirectory = root, UseShellExecute = false };
    info.ArgumentList.Add("build");
    info.ArgumentList.Add("-trimpath");
    info.ArgumentList.Add("-o");
    info.ArgumentList.Add(output);
    info.ArgumentList.Add(source);
    info.Environment["CGO_ENABLED"] = "0";
    info.Environment["GOTOOLCHAIN"] = "auto";
    var process = Process.Start(info) ?? throw new Exception("run go build");
    process.WaitForExit();
    if (process.ExitCode != 0)
    {
        throw new Exception($"go build {source} failed");
    }
    return output;
}

var root = RepositoryRoot();
var workspace = Directory.CreateTempSubdirectory("sesame-csharp-contract-").FullName;
try
{
    var sesameBinary = Build(root, workspace, "sesame", "./cmd/sesame");
    var fakeFylo = Build(root, workspace, "fake-fylo", "./internal/adapters/fylo/testdata/fakefylo");
    var fyloRoot = Path.Combine(workspace, "root");
    Directory.CreateDirectory(fyloRoot);

    using var client = new Client(new Options
    {
        Binary = sesameBinary,
        FyloBinary = fakeFylo,
        FyloRoot = fyloRoot,
    });

    // System operations report a storage-backed process.
    AreEqual("ok", Field(client.Ping(), "status"), "ping status");
    AreEqual("ok", Field(client.Readiness(), "status"), "readiness status");
    AreEqual("sesame", Field(client.Version(), "name"), "version name");
    AreEqual("True", Field(client.Metrics(), "storage_configured"), "storage configured");

    // Tenant and principal.
    var tenantId = Field(Object(client.TenantBootstrap("acme"), "tenant"), "tenant_id")!;
    var principal = client.PrincipalCreate(tenantId, "human", "email", "Alice@Example.com");
    var principalId = Field(principal, "principal_id")!;
    AreEqual("alice@example.com", Field(Object(principal, "identifier"), "value"),
        "the engine normalizes the identifier");

    // A duplicate claim returns the stable conflict code.
    AreEqual("identifier_conflict",
        CodeOf(() => client.PrincipalCreate(tenantId, "workload", "email", "alice@example.com")),
        "duplicate identifier");

    // Authorization: deny by default, allow after a grant, deny after revoke.
    var permissions = new List<IDictionary<string, object?>>
    {
        new Dictionary<string, object?> { ["action"] = "doc:read", ["resource"] = "project:*" },
    };
    var roleId = Field(client.RoleCreate(tenantId, "reader", permissions), "role_id")!;

    var denied = client.Decide(tenantId, principalId, "doc:read", "project:alpha");
    AreEqual("deny", Field(denied, "decision"), "pre-grant decision");
    AreEqual("deny_no_grant", Field(denied, "reason_code"), "pre-grant reason");

    var grantId = Field(client.GrantCreate(tenantId, principalId, roleId), "grant_id")!;
    var allowed = client.Decide(tenantId, principalId, "doc:read", "project:alpha");
    AreEqual("allow", Field(allowed, "decision"), "post-grant decision");
    AreEqual("allow_role_grant", Field(allowed, "reason_code"), "post-grant reason");

    client.GrantRevoke(grantId);
    AreEqual("deny",
        Field(client.Decide(tenantId, principalId, "doc:read", "project:alpha"), "decision"),
        "post-revoke decision");

    // Authentication: password login, session verification, revocation.
    const string password = "correct horse battery staple";
    client.SetPassword(principalId, password);
    var begun = client.AuthnBegin(tenantId, "email", "Alice@Example.com");
    AreEqual("awaiting_factor", Field(begun, "state"), "begin state");
    var transactionId = Field(begun, "transaction_id")!;

    var wrong = client.AuthnVerifyPassword(transactionId, "wrong password value");
    AreEqual("4", Field(wrong, "attempts_left"), "attempts after a wrong password");

    var verified = client.AuthnVerifyPassword(transactionId, password);
    AreEqual("password", Field(verified, "assurance"), "assurance");

    var issued = client.AuthnComplete(transactionId, 3600);
    var sessionId = Field(issued, "session_id")!;
    var secret = Field(issued, "session_secret")!;

    var session = client.SessionVerify(sessionId, secret);
    AreEqual(principalId, Field(session, "principal_id"), "verified session principal");
    AreEqual(null, Field(session, "secret_digest"),
        "the stored digest must not cross the boundary");

    AreEqual("session_not_found", CodeOf(() => client.SessionVerify(sessionId, "nope")),
        "wrong session secret");
    client.SessionRevoke(sessionId, "test");
    AreEqual("session_inactive", CodeOf(() => client.SessionVerify(sessionId, secret)),
        "revoked session");

    // An unknown identifier is indistinguishable from a known one.
    var unknown = client.AuthnBegin(tenantId, "email", "ghost@example.com");
    AreEqual(Field(begun, "state"), Field(unknown, "state"), "unknown identifier state");
    var attempt = client.AuthnVerifyPassword(Field(unknown, "transaction_id")!, password);
    AreEqual("4", Field(attempt, "attempts_left"), "unknown identifier attempts");
    AreEqual(null, Field(attempt, "assurance"), "unknown identifier assurance");

    // Unknown records return stable codes rather than transport failures.
    AreEqual("tenant_not_found", CodeOf(() => client.TenantGetByName("missing")), "missing tenant");
    AreEqual("operation_not_found", CodeOf(() => client.Request("identity.unknown")),
        "unknown operation");

    Console.WriteLine($"ok\tcsharp contract scenario\t{checks} checks");
}
finally
{
    Directory.Delete(workspace, recursive: true);
}
