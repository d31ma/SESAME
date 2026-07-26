//! Runs the shared SDK contract scenario against real compiled binaries.
//!
//! Every SESAME SDK drives this same sequence, so a divergence in any one
//! client fails its own suite rather than hiding behind a mock.

#[path = "sesame.rs"]
mod sesame;

use sesame::{Client, Error, Options, Value};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Finds the repository root by walking up from the working directory until
/// go.mod appears, so the test runs the same under cargo and plain rustc.
fn repository_root() -> PathBuf {
    let mut candidate = env::current_dir().expect("current directory");
    loop {
        if candidate.join("go.mod").is_file() {
            return candidate;
        }
        if !candidate.pop() {
            panic!("could not locate the repository root from the working directory");
        }
    }
}

fn build(root: &PathBuf, workspace: &PathBuf, name: &str, source: &str) -> PathBuf {
    let output = workspace.join(name);
    let status = Command::new("go")
        .args(["build", "-trimpath", "-o"])
        .arg(&output)
        .arg(source)
        .current_dir(root)
        .env("CGO_ENABLED", "0")
        .env("GOTOOLCHAIN", "auto")
        .status()
        .expect("run go build");
    assert!(status.success(), "go build {source} failed");
    output
}

fn expect_str(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key} in {value:?}"))
        .to_string()
}

#[test]
fn sdk_contract_scenario() {
    let root = repository_root();
    let workspace = env::temp_dir().join(format!("sesame-rust-contract-{}", std::process::id()));
    fs::create_dir_all(&workspace).expect("create workspace");

    let sesame_binary = build(&root, &workspace, "sesame", "./cmd/sesame");
    let fake_fylo = build(
        &root,
        &workspace,
        "fake-fylo",
        "./internal/adapters/fylo/testdata/fakefylo",
    );
    let fylo_root = workspace.join("root");
    fs::create_dir_all(&fylo_root).expect("create root");

    let mut client = Client::start(Options {
        binary: sesame_binary.to_string_lossy().into_owned(),
        fylo_binary: fake_fylo.to_string_lossy().into_owned(),
        fylo_root: fylo_root.to_string_lossy().into_owned(),
        ..Options::default()
    })
    .expect("start sesame");

    // System operations report a storage-backed process.
    assert_eq!(
        client.ping().expect("ping").get("status").and_then(Value::as_str),
        Some("ok")
    );
    assert_eq!(
        client
            .readiness()
            .expect("readiness")
            .get("status")
            .and_then(Value::as_str),
        Some("ok")
    );
    assert_eq!(
        client
            .version()
            .expect("version")
            .get("name")
            .and_then(Value::as_str),
        Some("sesame")
    );
    assert_eq!(
        client
            .metrics()
            .expect("metrics")
            .get("storage_configured")
            .and_then(Value::as_bool),
        Some(true)
    );

    // Standards dispatch pins contract v1 and rejects boundary injection.
    let standards = client
        .standards_dispatch(sesame::object(&[
            ("contract_version", "unsupported"),
            ("endpoint", "oidc.token"),
            ("method", "GET"),
        ]))
        .expect("standards.dispatch method response");
    assert_eq!(
        standards.get("contract_version").and_then(Value::as_str),
        Some("1")
    );
    assert_eq!(standards.get("status").and_then(Value::as_f64), Some(405.0));
    assert_eq!(
        standards
            .get("headers")
            .and_then(|headers| headers.get("allow"))
            .and_then(Value::as_str),
        Some("POST")
    );
    assert_eq!(
        standards
            .get("headers")
            .and_then(|headers| headers.get("content-type"))
            .and_then(Value::as_str),
        Some("application/json")
    );
    assert_eq!(
        standards
            .get("body")
            .and_then(|body| body.get("error"))
            .and_then(Value::as_str),
        Some("invalid_request")
    );

    let rejected = client
        .standards_dispatch(sesame::object(&[
            ("contract_version", "unsupported"),
            ("endpoint", "oidc.token"),
            ("method", "POST"),
            ("authorization", "Basic safe\r\nX-Injected: yes"),
        ]))
        .expect_err("control-character authorization");
    assert_eq!(rejected.code(), Some("invalid_request"));

    // Tenant and principal.
    let tenant = client.tenant_bootstrap("acme").expect("bootstrap");
    let tenant_id = expect_str(tenant.get("tenant").expect("tenant"), "tenant_id");
    let principal = client
        .principal_create(&tenant_id, "human", "email", "Alice@Example.com")
        .expect("principal.create");
    let principal_id = expect_str(&principal, "principal_id");
    assert_eq!(
        principal
            .get("identifier")
            .and_then(|identifier| identifier.get("value"))
            .and_then(Value::as_str),
        Some("alice@example.com"),
        "the engine normalizes the identifier"
    );

    // A duplicate claim returns the stable conflict code.
    let conflict = client
        .principal_create(&tenant_id, "workload", "email", "alice@example.com")
        .expect_err("duplicate identifier");
    assert_eq!(conflict.code(), Some("identifier_conflict"));

    // Authorization: deny by default, allow after a grant, deny after revoke.
    let mut permission = BTreeMap::new();
    permission.insert("action".to_string(), Value::String("doc:read".into()));
    permission.insert("resource".to_string(), Value::String("project:*".into()));
    let role = client
        .role_create(&tenant_id, "reader", vec![Value::Object(permission)])
        .expect("role.create");
    let role_id = expect_str(&role, "role_id");

    let denied = client
        .decide(&tenant_id, &principal_id, "doc:read", "project:alpha")
        .expect("decide");
    assert_eq!(denied.get("decision").and_then(Value::as_str), Some("deny"));
    assert_eq!(
        denied.get("reason_code").and_then(Value::as_str),
        Some("deny_no_grant")
    );

    let grant = client
        .grant_create(&tenant_id, &principal_id, &role_id)
        .expect("grant.create");
    let grant_id = expect_str(&grant, "grant_id");
    let allowed = client
        .decide(&tenant_id, &principal_id, "doc:read", "project:alpha")
        .expect("decide");
    assert_eq!(allowed.get("decision").and_then(Value::as_str), Some("allow"));
    assert_eq!(
        allowed.get("reason_code").and_then(Value::as_str),
        Some("allow_role_grant")
    );

    client.grant_revoke(&grant_id).expect("grant.revoke");
    let after_revoke = client
        .decide(&tenant_id, &principal_id, "doc:read", "project:alpha")
        .expect("decide");
    assert_eq!(
        after_revoke.get("decision").and_then(Value::as_str),
        Some("deny")
    );

    // Authentication: password login, session verification, revocation.
    let password = "correct horse battery staple";
    client
        .set_password(&principal_id, password)
        .expect("set_password");
    let begun = client
        .authn_begin(&tenant_id, "email", "Alice@Example.com")
        .expect("authn.begin");
    assert_eq!(
        begun.get("state").and_then(Value::as_str),
        Some("awaiting_factor")
    );
    let transaction_id = expect_str(&begun, "transaction_id");

    let wrong = client
        .authn_verify_password(&transaction_id, "wrong password value")
        .expect("wrong password");
    assert_eq!(wrong.get("attempts_left").and_then(Value::as_f64), Some(4.0));

    let verified = client
        .authn_verify_password(&transaction_id, password)
        .expect("verify");
    assert_eq!(
        verified.get("assurance").and_then(Value::as_str),
        Some("password")
    );

    let issued = client
        .authn_complete(&transaction_id, 3600)
        .expect("complete");
    let session_id = expect_str(&issued, "session_id");
    let secret = expect_str(&issued, "session_secret");

    let session = client
        .session_verify(&session_id, &secret)
        .expect("session.verify");
    assert_eq!(
        session.get("principal_id").and_then(Value::as_str),
        Some(principal_id.as_str())
    );
    assert!(
        session.get("secret_digest").is_none(),
        "the stored digest must not cross the boundary"
    );

    let wrong_secret = client
        .session_verify(&session_id, "nope")
        .expect_err("wrong secret");
    assert_eq!(wrong_secret.code(), Some("session_not_found"));

    client
        .session_revoke(&session_id, "test")
        .expect("session.revoke");
    let revoked = client
        .session_verify(&session_id, &secret)
        .expect_err("revoked session");
    assert_eq!(revoked.code(), Some("session_inactive"));

    // An unknown identifier is indistinguishable from a known one.
    let unknown = client
        .authn_begin(&tenant_id, "email", "ghost@example.com")
        .expect("unknown authn.begin");
    assert_eq!(
        unknown.get("state").and_then(Value::as_str),
        begun.get("state").and_then(Value::as_str)
    );
    let unknown_transaction = expect_str(&unknown, "transaction_id");
    let attempt = client
        .authn_verify_password(&unknown_transaction, password)
        .expect("unknown attempt");
    assert_eq!(attempt.get("attempts_left").and_then(Value::as_f64), Some(4.0));
    assert!(attempt.get("assurance").is_none());

    // Unknown records return stable codes rather than transport failures.
    let missing = client.tenant_get_by_name("missing").expect_err("missing tenant");
    assert_eq!(missing.code(), Some("tenant_not_found"));
    match client.request("identity.unknown", sesame::object(&[])) {
        Err(Error::Protocol(error)) => assert_eq!(error.code, "operation_not_found"),
        other => panic!("unknown operation = {other:?}"),
    }

    client.close().expect("close");
    let _ = fs::remove_dir_all(&workspace);
}
