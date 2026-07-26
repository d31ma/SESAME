//! A thin Rust client for a local SESAME process.
//!
//! The client owns process lifecycle, NDJSON framing, and typed transport
//! errors. Identity and authorization semantics remain in the SESAME
//! executable. Dependencies: the Rust standard library only, which means the
//! shim carries a minimal JSON reader and writer rather than pulling in a
//! crate; it handles exactly the protocol's shapes and rejects the rest.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROTOCOL_VERSION: &str = "1";

/// Bounds what a failing engine can make the caller hold: generous enough for
/// a refusal and its remedy, short of anything worth worrying about.
const STARTUP_DIAGNOSTICS_BYTES: usize = 4096;
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// One JSON value from the machine protocol.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    /// Returns a nested field, or None when absent or not an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(fields) => fields.get(key),
            _ => None,
        }
    }

    /// Returns the value as a string slice when it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    /// Returns the value as an f64 when it is a number.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(number) => Some(*number),
            _ => None,
        }
    }

    /// Returns the value as a bool when it is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Number(number) => {
                // Integral values are written without a fractional part so
                // the engine's integer fields round-trip exactly.
                if number.fract() == 0.0 && number.abs() < 9.0e15 {
                    out.push_str(&format!("{}", *number as i64));
                } else {
                    out.push_str(&format!("{number}"));
                }
            }
            Value::String(text) => write_json_string(text, out),
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Value::Object(fields) => {
                out.push('{');
                for (index, (key, item)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_json_string(key, out);
                    out.push(':');
                    item.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_json_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// A stable error returned by the SESAME machine interface.
#[derive(Debug, Clone)]
pub struct ProtocolError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sesame protocol error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}

/// Any failure a request can produce.
#[derive(Debug)]
pub enum Error {
    /// The engine answered with a stable protocol error.
    Protocol(ProtocolError),
    /// The transport failed or the response was not usable.
    Transport(String),
    /// The engine is one this client cannot speak to. Both sides are named,
    /// because the fix is always to change one of them.
    Incompatible {
        client_protocol_version: String,
        engine_protocol_version: String,
        engine_version: String,
        missing_operations: Vec<String>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protocol(error) => write!(formatter, "{error}"),
            Error::Transport(message) => write!(formatter, "sesame transport error: {message}"),
            Error::Incompatible {
                client_protocol_version,
                engine_protocol_version,
                engine_version,
                missing_operations,
            } => {
                if engine_protocol_version != client_protocol_version {
                    write!(
                        formatter,
                        "sesame engine {engine_version} speaks machine protocol \
                         {engine_protocol_version:?}; this client speaks \
                         {client_protocol_version:?}"
                    )
                } else {
                    write!(
                        formatter,
                        "sesame engine {} does not support {} operation(s) this client requires: {}",
                        engine_version,
                        missing_operations.len(),
                        missing_operations.join(", ")
                    )
                }
            }
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Returns the stable error code when this is a protocol error.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Protocol(error) => Some(&error.code),
            Error::Transport(_) | Error::Incompatible { .. } => None,
        }
    }
}

/// Startup options for the local SESAME process.
#[derive(Debug, Default, Clone)]
pub struct Options {
    pub binary: String,
    pub deployment: String,
    pub fylo_binary: String,
    pub fylo_root: String,
    /// Suppresses the protocol handshake `start` performs. For tests that
    /// deliberately drive a mismatched engine; production callers leave it
    /// false.
    pub skip_compatibility_check: bool,
}

/// Owns one long-lived local SESAME subprocess.
pub struct Client {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    counter: u64,
    closed: bool,
}

impl Client {
    /// Launches a SESAME subprocess in persistent machine mode.
    pub fn start(options: Options) -> Result<Self, Error> {
        // SESAME_BINARY names the engine when no option does; an explicit option still wins.
        let binary = if options.binary.is_empty() {
            std::env::var("SESAME_BINARY").unwrap_or_else(|_| "sesame".to_string())
        } else {
            options.binary.clone()
        };
        let mut command = Command::new(binary);
        command.arg("exec").arg("--loop");
        if !options.deployment.is_empty() {
            command.arg("--deployment").arg(&options.deployment);
        }
        if !options.fylo_binary.is_empty() || !options.fylo_root.is_empty() {
            command
                .arg("--fylo-binary")
                .arg(&options.fylo_binary)
                .arg("--fylo-root")
                .arg(&options.fylo_root);
        }
        // The engine reports a missing deployment or an unusable FYLO root on
        // stderr and then exits. Discarding that would leave the caller with a
        // dead process and no reason, so the startup window is captured.
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Error::Transport(format!("start sesame: {error}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Transport("sesame stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Transport("sesame stdout unavailable".into()))?;
        let mut client = Client {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            counter: 0,
            closed: false,
        };
        // A mismatched engine is found here rather than partway through a
        // security flow that then cannot finish. system.version needs no
        // storage, so this works before a FYLO root is configured.
        if !options.skip_compatibility_check {
            if let Err(error) = client.check_compatibility() {
                let diagnostic = client.startup_diagnostics();
                let _ = client.close();
                return Err(match diagnostic {
                    Some(detail) => Error::Transport(format!("{error}: {detail}")),
                    None => error,
                });
            }
        }
        Ok(client)
    }

    /// Reads what a failing engine said before it exited.
    fn startup_diagnostics(&mut self) -> Option<String> {
        let mut stderr = self.child.stderr.take()?;
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; STARTUP_DIAGNOSTICS_BYTES];
        if let Ok(read) = stderr.read(&mut chunk) {
            buffer.extend_from_slice(&chunk[..read]);
        }
        let detail = String::from_utf8_lossy(&buffer).trim().to_string();
        if detail.is_empty() {
            None
        } else {
            Some(detail)
        }
    }

    /// Fails unless the engine speaks this client's machine protocol.
    pub fn check_compatibility(&mut self) -> Result<Value, Error> {
        let version = self.version()?;
        let engine = version
            .get("protocol_version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if engine != PROTOCOL_VERSION {
            return Err(Error::Incompatible {
                client_protocol_version: PROTOCOL_VERSION.to_string(),
                engine_protocol_version: engine,
                engine_version: version
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                missing_operations: Vec::new(),
            });
        }
        Ok(version)
    }

    /// Fails unless the engine routes every named operation. Call it at
    /// startup with what the application depends on: finding out here beats an
    /// operation_not_found in the middle of a login.
    pub fn require_operations(&mut self, operations: &[&str]) -> Result<Value, Error> {
        let version = self.version()?;
        let routed: Vec<String> = match version.get("operations") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        };
        let mut missing: Vec<String> = operations
            .iter()
            .filter(|operation| !routed.iter().any(|routed| routed == *operation))
            .map(|operation| (*operation).to_string())
            .collect();
        if !missing.is_empty() {
            missing.sort();
            return Err(Error::Incompatible {
                client_protocol_version: PROTOCOL_VERSION.to_string(),
                engine_protocol_version: version
                    .get("protocol_version")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                engine_version: version
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                missing_operations: missing,
            });
        }
        Ok(version)
    }

    /// Sends one operation and returns its result.
    pub fn request(&mut self, operation: &str, parameters: Value) -> Result<Value, Error> {
        if self.closed {
            return Err(Error::Transport("sesame client is closed".into()));
        }
        self.counter += 1;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos())
            .unwrap_or(0);
        let request_id = format!("rs-{}-{}", nanos, self.counter);

        let mut frame = String::new();
        let mut envelope = BTreeMap::new();
        envelope.insert("protocol_version".into(), Value::String(PROTOCOL_VERSION.into()));
        envelope.insert("request_id".into(), Value::String(request_id.clone()));
        envelope.insert("operation".into(), Value::String(operation.into()));
        envelope.insert("parameters".into(), parameters);
        Value::Object(envelope).write(&mut frame);
        if frame.len() > MAX_FRAME_BYTES {
            return Err(Error::Transport("request exceeds the maximum frame size".into()));
        }
        frame.push('\n');

        self.stdin
            .write_all(frame.as_bytes())
            .and_then(|_| self.stdin.flush())
            .map_err(|error| Error::Transport(format!("write request: {error}")))?;

        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .map_err(|error| Error::Transport(format!("read response: {error}")))?;
        if read == 0 {
            return Err(Error::Transport("sesame process exited".into()));
        }
        decode_response(&request_id, &line)
    }

    /// Asks the child to exit and waits for it.
    pub fn close(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // Dropping stdin closes it, which ends the child's read loop.
        let _ = self.stdin.flush();
        let stdin = std::mem::replace(&mut self.stdin, {
            // A closed client never writes again; this placeholder is only
            // needed because ChildStdin has no default.
            let mut placeholder = Command::new("true")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| Error::Transport(format!("close: {error}")))?;
            let taken = placeholder.stdin.take().unwrap();
            let _ = placeholder.wait();
            taken
        });
        drop(stdin);
        self.child
            .wait()
            .map(|_| ())
            .map_err(|error| Error::Transport(format!("wait for sesame: {error}")))
    }

    // System operations.
    pub fn ping(&mut self) -> Result<Value, Error> {
        self.request("system.ping", object(&[]))
    }
    pub fn version(&mut self) -> Result<Value, Error> {
        self.request("system.version", object(&[]))
    }
    pub fn readiness(&mut self) -> Result<Value, Error> {
        self.request("system.readiness", object(&[]))
    }
    pub fn metrics(&mut self) -> Result<Value, Error> {
        self.request("system.metrics", object(&[]))
    }

    // Tenants and principals.
    pub fn tenant_bootstrap(&mut self, name: &str) -> Result<Value, Error> {
        self.request("tenant.bootstrap", object(&[("name", name)]))
    }
    pub fn tenant_get_by_name(&mut self, name: &str) -> Result<Value, Error> {
        self.request("tenant.get", object(&[("name", name)]))
    }
    pub fn principal_create(
        &mut self,
        tenant_id: &str,
        kind: &str,
        namespace: &str,
        value: &str,
    ) -> Result<Value, Error> {
        self.request(
            "principal.create",
            object(&[
                ("tenant_id", tenant_id),
                ("kind", kind),
                ("identifier_namespace", namespace),
                ("identifier_value", value),
            ]),
        )
    }
    pub fn principal_get_by_id(&mut self, principal_id: &str) -> Result<Value, Error> {
        self.request("principal.get", object(&[("principal_id", principal_id)]))
    }
    pub fn principal_suspend(&mut self, principal_id: &str) -> Result<Value, Error> {
        self.request("principal.suspend", object(&[("principal_id", principal_id)]))
    }

    // Authorization.
    pub fn role_create(
        &mut self,
        tenant_id: &str,
        name: &str,
        permissions: Vec<Value>,
    ) -> Result<Value, Error> {
        let mut fields = BTreeMap::new();
        fields.insert("tenant_id".into(), Value::String(tenant_id.into()));
        fields.insert("name".into(), Value::String(name.into()));
        fields.insert("permissions".into(), Value::Array(permissions));
        self.request("role.create", Value::Object(fields))
    }
    pub fn grant_create(
        &mut self,
        tenant_id: &str,
        principal_id: &str,
        role_id: &str,
    ) -> Result<Value, Error> {
        self.request(
            "grant.create",
            object(&[
                ("tenant_id", tenant_id),
                ("principal_id", principal_id),
                ("role_id", role_id),
            ]),
        )
    }
    pub fn grant_revoke(&mut self, grant_id: &str) -> Result<Value, Error> {
        self.request("grant.revoke", object(&[("grant_id", grant_id)]))
    }
    /// Asks the same question as decide, but proves a session instead of naming
    /// a principal.
    ///
    /// The engine verifies the session and derives context under the reserved
    /// "session." prefix, so a caller cannot assert its own assurance level.
    /// That is what makes a step-up condition worth trusting.
    pub fn decide_for_session(
        &mut self,
        tenant_id: &str,
        session_id: &str,
        session_secret: &str,
        action: &str,
        resource: &str,
    ) -> Result<Value, Error> {
        self.request(
            "authorize.decide",
            object(&[
                ("tenant_id", tenant_id),
                ("session_id", session_id),
                ("session_secret", session_secret),
                ("action", action),
                ("resource", resource),
            ]),
        )
    }

    pub fn decide(
        &mut self,
        tenant_id: &str,
        principal_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<Value, Error> {
        self.request(
            "authorize.decide",
            object(&[
                ("tenant_id", tenant_id),
                ("principal_id", principal_id),
                ("action", action),
                ("resource", resource),
            ]),
        )
    }

    // Authentication.
    pub fn set_password(&mut self, principal_id: &str, password: &str) -> Result<Value, Error> {
        self.request(
            "authenticator.set_password",
            object(&[("principal_id", principal_id), ("password", password)]),
        )
    }
    /// Starts a login transaction. It succeeds whether or not the identifier
    /// resolves, so the result never reveals which identifiers exist.
    pub fn authn_begin(
        &mut self,
        tenant_id: &str,
        namespace: &str,
        value: &str,
    ) -> Result<Value, Error> {
        self.request(
            "authn.begin",
            object(&[
                ("tenant_id", tenant_id),
                ("identifier_namespace", namespace),
                ("identifier_value", value),
            ]),
        )
    }
    pub fn authn_verify_password(
        &mut self,
        transaction_id: &str,
        password: &str,
    ) -> Result<Value, Error> {
        self.request(
            "authn.verify_password",
            object(&[("transaction_id", transaction_id), ("password", password)]),
        )
    }
    pub fn authn_complete(
        &mut self,
        transaction_id: &str,
        lifetime_seconds: i64,
    ) -> Result<Value, Error> {
        let mut fields = BTreeMap::new();
        fields.insert("transaction_id".into(), Value::String(transaction_id.into()));
        fields.insert(
            "lifetime_seconds".into(),
            Value::Number(lifetime_seconds as f64),
        );
        self.request("authn.complete", Value::Object(fields))
    }
    pub fn session_verify(&mut self, session_id: &str, secret: &str) -> Result<Value, Error> {
        self.request(
            "session.verify",
            object(&[("session_id", session_id), ("session_secret", secret)]),
        )
    }
    pub fn session_revoke(&mut self, session_id: &str, reason: &str) -> Result<Value, Error> {
        self.request(
            "session.revoke",
            object(&[("session_id", session_id), ("reason", reason)]),
        )
    }

    // ---- Groups and administration ---------------------------------------
    pub fn group_create(&mut self, tenant_id: &str, name: &str) -> Result<Value, Error> {
        self.request(
            "group.create",
            object(&[("tenant_id", tenant_id), ("name", name)]),
        )
    }
    pub fn group_member_add(&mut self, group_id: &str, principal_id: &str) -> Result<Value, Error> {
        self.request(
            "group.member_add",
            object(&[("group_id", group_id), ("principal_id", principal_id)]),
        )
    }
    pub fn group_member_remove(
        &mut self,
        group_id: &str,
        principal_id: &str,
    ) -> Result<Value, Error> {
        self.request(
            "group.member_remove",
            object(&[("group_id", group_id), ("principal_id", principal_id)]),
        )
    }
    pub fn admin_bootstrap(
        &mut self,
        tenant_name: &str,
        namespace: &str,
        value: &str,
    ) -> Result<Value, Error> {
        self.request(
            "admin.bootstrap",
            object(&[
                ("tenant_name", tenant_name),
                ("identifier_namespace", namespace),
                ("identifier_value", value),
            ]),
        )
    }
    /// A batch always answers under one policy version.
    pub fn decide_batch(&mut self, requests: Vec<Value>) -> Result<Value, Error> {
        self.request(
            "authorize.decide_batch",
            fields(vec![("requests", Value::Array(requests))]),
        )
    }

    // ---- Second factors ---------------------------------------------------
    //
    // The shared secret is returned once at enrolment and is never recoverable
    // afterwards. A TOTP code spends its time step durably, so an observed
    // code cannot be replayed even inside its own window.
    pub fn totp_enroll(&mut self, principal_id: &str, issuer: &str) -> Result<Value, Error> {
        self.request(
            "authenticator.totp_enroll",
            object(&[("principal_id", principal_id), ("issuer", issuer)]),
        )
    }
    pub fn totp_activate(&mut self, principal_id: &str, code: &str) -> Result<Value, Error> {
        self.request(
            "authenticator.totp_activate",
            object(&[("principal_id", principal_id), ("code", code)]),
        )
    }
    pub fn authn_verify_totp(&mut self, transaction_id: &str, code: &str) -> Result<Value, Error> {
        self.request(
            "authn.verify_totp",
            object(&[("transaction_id", transaction_id), ("code", code)]),
        )
    }
    /// Returns ten single-use codes once, retiring any previous set.
    pub fn recovery_codes_issue(&mut self, principal_id: &str) -> Result<Value, Error> {
        self.request(
            "authenticator.recovery_codes_issue",
            object(&[("principal_id", principal_id)]),
        )
    }
    pub fn authn_verify_recovery_code(
        &mut self,
        transaction_id: &str,
        code: &str,
    ) -> Result<Value, Error> {
        self.request(
            "authn.verify_recovery_code",
            object(&[("transaction_id", transaction_id), ("code", code)]),
        )
    }

    // ---- OIDC relying parties ---------------------------------------------
    //
    // An omitted audience is treated as third party, the stricter rule: such a
    // client needs recorded user consent before it receives a code.
    pub fn oidc_client_register(
        &mut self,
        tenant_id: &str,
        name: &str,
        client_type: &str,
        redirect_uris: &[&str],
        scopes: &[&str],
        audience: &str,
        post_logout_redirect_uris: &[&str],
    ) -> Result<Value, Error> {
        self.request(
            "oidc_client.register",
            fields(vec![
                ("tenant_id", Value::String(tenant_id.to_string())),
                ("name", Value::String(name.to_string())),
                ("client_type", Value::String(client_type.to_string())),
                ("redirect_uris", strings(redirect_uris)),
                ("scopes", strings(scopes)),
                ("audience", Value::String(audience.to_string())),
                ("post_logout_redirect_uris", strings(post_logout_redirect_uris)),
            ]),
        )
    }
    pub fn oidc_client_get(&mut self, client_id: &str) -> Result<Value, Error> {
        self.request("oidc_client.get", object(&[("client_id", client_id)]))
    }
    pub fn oidc_client_rotate_secret(&mut self, client_id: &str) -> Result<Value, Error> {
        self.request(
            "oidc_client.rotate_secret",
            object(&[("client_id", client_id)]),
        )
    }
    pub fn oidc_client_disable(&mut self, client_id: &str, reason: &str) -> Result<Value, Error> {
        self.request(
            "oidc_client.disable",
            object(&[("client_id", client_id), ("reason", reason)]),
        )
    }

    // ---- The external interaction contract --------------------------------
    //
    // `authorize` validates the whole request before anything is shown to a
    // user. The returned secret authorizes completing that one interaction.
    pub fn authorize(&mut self, request: Value) -> Result<Value, Error> {
        self.request("oidc.authorize", request)
    }
    pub fn interaction_get(&mut self, interaction_id: &str) -> Result<Value, Error> {
        self.request(
            "oidc.interaction_get",
            object(&[("interaction_id", interaction_id)]),
        )
    }
    pub fn interaction_complete(
        &mut self,
        interaction_id: &str,
        interaction_secret: &str,
        session_id: &str,
        session_secret: &str,
    ) -> Result<Value, Error> {
        self.request(
            "oidc.interaction_complete",
            object(&[
                ("interaction_id", interaction_id),
                ("interaction_secret", interaction_secret),
                ("session_id", session_id),
                ("session_secret", session_secret),
            ]),
        )
    }
    /// A refresh response carries a new refresh token that replaces the one
    /// presented; continuing to use the old one revokes the whole family.
    /// Checks a key-bound access token against a fresh proof (RFC 9449).
    pub fn dpop_verify(
        &mut self,
        access_token: &str,
        proof: &str,
        method: &str,
        uri: &str,
    ) -> Result<Value, Error> {
        self.request(
            "oidc.dpop_verify",
            Value::Object(vec![
                ("access_token".to_string(), Value::String(access_token.to_string())),
                ("dpop_proof".to_string(), Value::String(proof.to_string())),
                ("http_method".to_string(), Value::String(method.to_string())),
                ("http_uri".to_string(), Value::String(uri.to_string())),
            ]),
        )
    }

    /// Pushes an authorization request on the back channel (RFC 9126).
    pub fn pushed_authorize(&mut self, request: Value) -> Result<Value, Error> {
        self.request("oidc.pushed_authorize", request)
    }

    /// The device grant (RFC 8628). `device_authorize` starts it; the person
    /// types the user code elsewhere and approves or denies it there.
    pub fn device_authorize(&mut self, client_id: &str, scopes: &[&str]) -> Result<Value, Error> {
        self.request(
            "oidc.device_authorize",
            fields(vec![
                ("client_id", Value::String(client_id.to_string())),
                ("scopes", strings(scopes)),
            ]),
        )
    }

    pub fn device_lookup(&mut self, tenant_id: &str, user_code: &str) -> Result<Value, Error> {
        self.request(
            "oidc.device_lookup",
            object(&[("tenant_id", tenant_id), ("user_code", user_code)]),
        )
    }

    pub fn device_approve(
        &mut self,
        tenant_id: &str,
        user_code: &str,
        session_id: &str,
        session_secret: &str,
    ) -> Result<Value, Error> {
        self.request(
            "oidc.device_approve",
            object(&[
                ("tenant_id", tenant_id),
                ("user_code", user_code),
                ("session_id", session_id),
                ("session_secret", session_secret),
            ]),
        )
    }

    pub fn device_deny(&mut self, tenant_id: &str, user_code: &str) -> Result<Value, Error> {
        self.request(
            "oidc.device_deny",
            object(&[("tenant_id", tenant_id), ("user_code", user_code)]),
        )
    }

    pub fn token_exchange(&mut self, request: Value) -> Result<Value, Error> {
        self.request("oidc.token", request)
    }
    pub fn refresh_family_revoke(&mut self, family_id: &str, reason: &str) -> Result<Value, Error> {
        self.request(
            "oidc.refresh_family_revoke",
            object(&[("family_id", family_id), ("reason", reason)]),
        )
    }
    pub fn refresh_family_get(&mut self, family_id: &str) -> Result<Value, Error> {
        self.request(
            "oidc.refresh_family_get",
            object(&[("family_id", family_id)]),
        )
    }

    // ---- Consent -----------------------------------------------------------
    //
    // The session proves who is agreeing, so a caller cannot consent on
    // somebody else's behalf. Withdrawing also revokes that client's refresh
    // families for the principal.
    pub fn consent_grant(
        &mut self,
        session_id: &str,
        session_secret: &str,
        client_id: &str,
        scopes: &[&str],
    ) -> Result<Value, Error> {
        self.request(
            "oidc.consent_grant",
            fields(vec![
                ("session_id", Value::String(session_id.to_string())),
                ("session_secret", Value::String(session_secret.to_string())),
                ("client_id", Value::String(client_id.to_string())),
                ("scopes", strings(scopes)),
            ]),
        )
    }
    pub fn consent_withdraw(
        &mut self,
        principal_id: &str,
        client_id: &str,
    ) -> Result<Value, Error> {
        self.request(
            "oidc.consent_withdraw",
            object(&[("principal_id", principal_id), ("client_id", client_id)]),
        )
    }
    pub fn consent_get(&mut self, principal_id: &str, client_id: &str) -> Result<Value, Error> {
        self.request(
            "oidc.consent_get",
            object(&[("principal_id", principal_id), ("client_id", client_id)]),
        )
    }

    // ---- Standards surfaces ------------------------------------------------
    //
    // Endpoint paths are the host's own; the engine composes them under the
    // configured issuer and refuses any that would leave that origin.
    pub fn discovery(&mut self, endpoints: Value) -> Result<Value, Error> {
        self.request("oidc.discovery", endpoints)
    }
    pub fn signing_keys(&mut self) -> Result<Value, Error> {
        self.request("token.jwks", Value::Object(BTreeMap::new()))
    }
    /// Introspection reports live grant state, not just signature validity:
    /// this is where a revoked session shows up.
    pub fn introspect(
        &mut self,
        client_id: &str,
        client_secret: &str,
        token: &str,
    ) -> Result<Value, Error> {
        self.request(
            "oidc.introspect",
            object(&[
                ("token", token),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ]),
        )
    }
    pub fn revoke(
        &mut self,
        client_id: &str,
        client_secret: &str,
        token: &str,
    ) -> Result<Value, Error> {
        self.request(
            "oidc.revoke",
            object(&[
                ("token", token),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ]),
        )
    }
    /// The hint is required and may be expired; revoking its session also ends
    /// every refresh grant resting on it.
    pub fn logout(
        &mut self,
        id_token_hint: &str,
        post_logout_redirect_uri: &str,
        state: &str,
    ) -> Result<Value, Error> {
        self.request(
            "oidc.logout",
            object(&[
                ("id_token_hint", id_token_hint),
                ("post_logout_redirect_uri", post_logout_redirect_uri),
                ("state", state),
            ]),
        )
    }

    // ---- Passkeys -----------------------------------------------------------
    //
    // Binary values cross the protocol as base64. A user-verified passkey
    // establishes MFA on its own, with no prior factor.
    pub fn passkey_register_begin(&mut self, principal_id: &str) -> Result<Value, Error> {
        self.request(
            "authenticator.passkey_register_begin",
            object(&[("principal_id", principal_id)]),
        )
    }
    pub fn passkey_register_finish(
        &mut self,
        principal_id: &str,
        attestation_object: &[u8],
        client_data_json: &[u8],
    ) -> Result<Value, Error> {
        self.request(
            "authenticator.passkey_register_finish",
            object(&[
                ("principal_id", principal_id),
                ("attestation_object", &base64url(attestation_object)),
                ("client_data_json", &base64url(client_data_json)),
            ]),
        )
    }
    pub fn passkey_list(&mut self, principal_id: &str) -> Result<Value, Error> {
        self.request(
            "authenticator.passkey_list",
            object(&[("principal_id", principal_id)]),
        )
    }
    pub fn passkey_remove(&mut self, credential_id: &str) -> Result<Value, Error> {
        self.request(
            "authenticator.passkey_remove",
            object(&[("credential_id", credential_id)]),
        )
    }
    pub fn passkey_options(&mut self, transaction_id: &str) -> Result<Value, Error> {
        self.request(
            "authn.passkey_options",
            object(&[("transaction_id", transaction_id)]),
        )
    }
    pub fn authn_verify_passkey(
        &mut self,
        transaction_id: &str,
        credential_id: &str,
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
    ) -> Result<Value, Error> {
        self.request(
            "authn.verify_passkey",
            object(&[
                ("transaction_id", transaction_id),
                ("credential_id", credential_id),
                ("authenticator_data", &base64url(authenticator_data)),
                ("client_data_json", &base64url(client_data_json)),
                ("signature", &base64url(signature)),
            ]),
        )
    }

    // ---- Inbound OIDC federation -------------------------------------------
    //
    // The engine performs no network I/O: register and configure return the
    // exact URL the host must fetch, and every document the host brings back
    // is validated in the engine as untrusted input.
    #[allow(clippy::too_many_arguments)]
    // ---- SCIM 2.0 provisioning -----------------------------------------
    //
    // Every resource operation carries the bearer token, so the engine always
    // authenticates and a host cannot forget to.
    pub fn provisioning_client_register(
        &mut self,
        tenant_id: &str,
        name: &str,
        identifier_namespace: &str,
        can_manage_groups: bool,
    ) -> Result<Value, Error> {
        self.request(
            "scim.client_register",
            fields(vec![
                ("tenant_id", Value::String(tenant_id.to_string())),
                ("name", Value::String(name.to_string())),
                ("identifier_namespace", Value::String(identifier_namespace.to_string())),
                ("can_manage_groups", Value::Bool(can_manage_groups)),
            ]),
        )
    }

    pub fn provisioning_client_disable(
        &mut self,
        tenant_id: &str,
        scim_client_id: &str,
        reason: &str,
    ) -> Result<Value, Error> {
        self.request(
            "scim.client_disable",
            object(&[
                ("tenant_id", tenant_id),
                ("scim_client_id", scim_client_id),
                ("reason", reason),
            ]),
        )
    }

    pub fn provisioning_client_rotate_token(
        &mut self,
        tenant_id: &str,
        scim_client_id: &str,
    ) -> Result<Value, Error> {
        self.request(
            "scim.client_rotate_token",
            object(&[("tenant_id", tenant_id), ("scim_client_id", scim_client_id)]),
        )
    }

    // SCIM Group provisioning. These require the client's can_manage_groups
    // grant: group membership drives authorization decisions.
    pub fn scim_group_create(&mut self, token: &str, body: &str) -> Result<Value, Error> {
        self.request("scim.group_create", object(&[("token", token), ("body", body)]))
    }

    pub fn scim_group_get(&mut self, token: &str, resource_id: &str) -> Result<Value, Error> {
        self.request(
            "scim.group_get",
            object(&[("token", token), ("resource_id", resource_id)]),
        )
    }

    pub fn scim_group_list(
        &mut self,
        token: &str,
        filter: &str,
        start_index: i64,
        count: i64,
    ) -> Result<Value, Error> {
        self.request(
            "scim.group_list",
            fields(vec![
                ("token", Value::String(token.to_string())),
                ("filter", Value::String(filter.to_string())),
                ("start_index", Value::Number(start_index as f64)),
                ("count", Value::Number(count as f64)),
            ]),
        )
    }

    pub fn scim_group_patch(
        &mut self,
        token: &str,
        resource_id: &str,
        body: &str,
    ) -> Result<Value, Error> {
        self.request(
            "scim.group_patch",
            object(&[("token", token), ("resource_id", resource_id), ("body", body)]),
        )
    }

    pub fn scim_group_deprovision(
        &mut self,
        token: &str,
        resource_id: &str,
    ) -> Result<Value, Error> {
        self.request(
            "scim.group_deprovision",
            object(&[("token", token), ("resource_id", resource_id)]),
        )
    }

    pub fn scim_user_create(&mut self, token: &str, body: &str) -> Result<Value, Error> {
        self.request("scim.user_create", object(&[("token", token), ("body", body)]))
    }

    pub fn scim_user_get(&mut self, token: &str, resource_id: &str) -> Result<Value, Error> {
        self.request(
            "scim.user_get",
            object(&[("token", token), ("resource_id", resource_id)]),
        )
    }

    pub fn scim_user_list(
        &mut self,
        token: &str,
        filter: &str,
        start_index: i64,
        count: i64,
    ) -> Result<Value, Error> {
        self.request(
            "scim.user_list",
            fields(vec![
                ("token", Value::String(token.to_string())),
                ("filter", Value::String(filter.to_string())),
                ("start_index", Value::Number(start_index as f64)),
                ("count", Value::Number(count as f64)),
            ]),
        )
    }

    pub fn scim_user_patch(
        &mut self,
        token: &str,
        resource_id: &str,
        body: &str,
    ) -> Result<Value, Error> {
        self.request(
            "scim.user_patch",
            object(&[("token", token), ("resource_id", resource_id), ("body", body)]),
        )
    }

    pub fn scim_user_deprovision(
        &mut self,
        token: &str,
        resource_id: &str,
    ) -> Result<Value, Error> {
        self.request(
            "scim.user_deprovision",
            object(&[("token", token), ("resource_id", resource_id)]),
        )
    }

    pub fn provider_register(
        &mut self,
        tenant_id: &str,
        name: &str,
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        scopes: &[&str],
        subject_claim: &str,
        email_claim: &str,
        linking: &str,
    ) -> Result<Value, Error> {
        self.request(
            "federation.provider_register",
            fields(vec![
                ("tenant_id", Value::String(tenant_id.to_string())),
                ("name", Value::String(name.to_string())),
                ("issuer", Value::String(issuer.to_string())),
                ("client_id", Value::String(client_id.to_string())),
                ("client_secret", Value::String(client_secret.to_string())),
                ("scopes", strings(scopes)),
                ("subject_claim", Value::String(subject_claim.to_string())),
                ("email_claim", Value::String(email_claim.to_string())),
                ("linking", Value::String(linking.to_string())),
            ]),
        )
    }

    pub fn saml_provider_register(
        &mut self,
        tenant_id: &str,
        name: &str,
        entity_id: &str,
        sso_url: &str,
        certificates: &[&str],
        identifier_namespace: &str,
        linking: &str,
    ) -> Result<Value, Error> {
        self.request(
            "saml.provider_register",
            fields(vec![
                ("tenant_id", Value::String(tenant_id.to_string())),
                ("name", Value::String(name.to_string())),
                ("entity_id", Value::String(entity_id.to_string())),
                ("sso_url", Value::String(sso_url.to_string())),
                ("certificates", strings(certificates)),
                (
                    "identifier_namespace",
                    Value::String(identifier_namespace.to_string()),
                ),
                ("linking", Value::String(linking.to_string())),
            ]),
        )
    }

    pub fn saml_provider_get(&mut self, tenant_id: &str, provider_id: &str) -> Result<Value, Error> {
        self.request(
            "saml.provider_get",
            object(&[("tenant_id", tenant_id), ("provider_id", provider_id)]),
        )
    }

    pub fn saml_provider_disable(
        &mut self,
        tenant_id: &str,
        provider_id: &str,
        reason: &str,
    ) -> Result<Value, Error> {
        self.request(
            "saml.provider_disable",
            object(&[
                ("tenant_id", tenant_id),
                ("provider_id", provider_id),
                ("reason", reason),
            ]),
        )
    }

    pub fn saml_login_start(
        &mut self,
        tenant_id: &str,
        provider_id: &str,
        consumer_url: &str,
    ) -> Result<Value, Error> {
        self.request(
            "saml.login_start",
            object(&[
                ("tenant_id", tenant_id),
                ("provider_id", provider_id),
                ("consumer_url", consumer_url),
            ]),
        )
    }

    pub fn saml_login_complete(
        &mut self,
        tenant_id: &str,
        login_id: &str,
        assertion: &str,
    ) -> Result<Value, Error> {
        self.request(
            "saml.login_complete",
            object(&[
                ("tenant_id", tenant_id),
                ("login_id", login_id),
                ("assertion", assertion),
            ]),
        )
    }

    pub fn provider_configure(
        &mut self,
        tenant_id: &str,
        provider_id: &str,
        discovery_document: &str,
        key_set_document: &str,
    ) -> Result<Value, Error> {
        self.request(
            "federation.provider_configure",
            object(&[
                ("tenant_id", tenant_id),
                ("provider_id", provider_id),
                ("discovery_document", discovery_document),
                ("key_set_document", key_set_document),
            ]),
        )
    }

    pub fn provider_disable(
        &mut self,
        tenant_id: &str,
        provider_id: &str,
        reason: &str,
    ) -> Result<Value, Error> {
        self.request(
            "federation.provider_disable",
            object(&[
                ("tenant_id", tenant_id),
                ("provider_id", provider_id),
                ("reason", reason),
            ]),
        )
    }

    pub fn provider_get(&mut self, tenant_id: &str, provider_id: &str) -> Result<Value, Error> {
        self.request(
            "federation.provider_get",
            object(&[("tenant_id", tenant_id), ("provider_id", provider_id)]),
        )
    }

    pub fn federated_login_start(
        &mut self,
        tenant_id: &str,
        provider_id: &str,
        redirect_uri: &str,
    ) -> Result<Value, Error> {
        self.request(
            "federation.login_start",
            object(&[
                ("tenant_id", tenant_id),
                ("provider_id", provider_id),
                ("redirect_uri", redirect_uri),
            ]),
        )
    }

    pub fn federated_login_exchange(
        &mut self,
        tenant_id: &str,
        login_id: &str,
        state: &str,
        code: &str,
    ) -> Result<Value, Error> {
        self.request(
            "federation.login_exchange",
            object(&[
                ("tenant_id", tenant_id),
                ("login_id", login_id),
                ("state", state),
                ("code", code),
            ]),
        )
    }

    pub fn federated_login_complete(
        &mut self,
        tenant_id: &str,
        login_id: &str,
        id_token: &str,
    ) -> Result<Value, Error> {
        self.request(
            "federation.login_complete",
            object(&[
                ("tenant_id", tenant_id),
                ("login_id", login_id),
                ("id_token", id_token),
            ]),
        )
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}


/// Builds an object whose values are already `Value`s, for the operations
/// that carry arrays alongside strings.
pub fn fields(pairs: Vec<(&str, Value)>) -> Value {
    let mut object = BTreeMap::new();
    for (key, value) in pairs {
        object.insert(key.to_string(), value);
    }
    Value::Object(object)
}

/// Builds a string array.
pub fn strings(values: &[&str]) -> Value {
    Value::Array(values.iter().map(|v| Value::String((*v).to_string())).collect())
}

/// Encodes a binary WebAuthn value for transport as unpadded base64url.
///
/// Written out rather than pulled in: the shim is standard-library only, and
/// this is the one place it needs an encoder.
pub fn base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let packed = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
        let encoded = [
            ALPHABET[((packed >> 18) & 63) as usize],
            ALPHABET[((packed >> 12) & 63) as usize],
            ALPHABET[((packed >> 6) & 63) as usize],
            ALPHABET[(packed & 63) as usize],
        ];
        // Unpadded: emit only the characters the input actually filled.
        let keep = chunk.len() + 1;
        for &character in &encoded[..keep] {
            out.push(character as char);
        }
    }
    out
}

/// Builds a flat string object, the shape most operations need.
pub fn object(pairs: &[(&str, &str)]) -> Value {
    let mut fields = BTreeMap::new();
    for (key, value) in pairs {
        fields.insert((*key).to_string(), Value::String((*value).to_string()));
    }
    Value::Object(fields)
}

fn decode_response(request_id: &str, line: &str) -> Result<Value, Error> {
    let response = parse(line).map_err(|error| Error::Transport(format!("decode: {error}")))?;
    match response.get("protocol_version").and_then(Value::as_str) {
        Some(PROTOCOL_VERSION) => {}
        other => {
            return Err(Error::Transport(format!(
                "unsupported protocol version {other:?}"
            )))
        }
    }
    match response.get("request_id").and_then(Value::as_str) {
        Some(id) if id == request_id => {}
        other => {
            return Err(Error::Transport(format!(
                "response request ID mismatch: expected {request_id}, received {other:?}"
            )))
        }
    }
    let ok = response
        .get("ok")
        .and_then(Value::as_bool)
        .ok_or_else(|| Error::Transport("response has no ok field".into()))?;
    if !ok {
        let error = response
            .get("error")
            .ok_or_else(|| Error::Transport("failure response has no error".into()))?;
        return Err(Error::Protocol(ProtocolError {
            code: error.get("code").and_then(Value::as_str).unwrap_or("").into(),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
            retryable: error.get("retryable").and_then(Value::as_bool).unwrap_or(false),
        }));
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

// A minimal JSON reader. It accepts the protocol's shapes and rejects
// anything else rather than guessing.
pub fn parse(text: &str) -> Result<Value, String> {
    let bytes: Vec<char> = text.chars().collect();
    let mut cursor = 0usize;
    let value = parse_value(&bytes, &mut cursor)?;
    skip_whitespace(&bytes, &mut cursor);
    if cursor != bytes.len() {
        return Err("trailing content after JSON value".into());
    }
    Ok(value)
}

fn skip_whitespace(bytes: &[char], cursor: &mut usize) {
    while *cursor < bytes.len() && bytes[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
}

fn parse_value(bytes: &[char], cursor: &mut usize) -> Result<Value, String> {
    skip_whitespace(bytes, cursor);
    if *cursor >= bytes.len() {
        return Err("unexpected end of input".into());
    }
    match bytes[*cursor] {
        '{' => parse_object(bytes, cursor),
        '[' => parse_array(bytes, cursor),
        '"' => parse_string(bytes, cursor).map(Value::String),
        't' => expect(bytes, cursor, "true").map(|_| Value::Bool(true)),
        'f' => expect(bytes, cursor, "false").map(|_| Value::Bool(false)),
        'n' => expect(bytes, cursor, "null").map(|_| Value::Null),
        _ => parse_number(bytes, cursor),
    }
}

fn expect(bytes: &[char], cursor: &mut usize, literal: &str) -> Result<(), String> {
    for expected in literal.chars() {
        if *cursor >= bytes.len() || bytes[*cursor] != expected {
            return Err(format!("expected {literal}"));
        }
        *cursor += 1;
    }
    Ok(())
}

fn parse_object(bytes: &[char], cursor: &mut usize) -> Result<Value, String> {
    *cursor += 1; // consume '{'
    let mut fields = BTreeMap::new();
    skip_whitespace(bytes, cursor);
    if *cursor < bytes.len() && bytes[*cursor] == '}' {
        *cursor += 1;
        return Ok(Value::Object(fields));
    }
    loop {
        skip_whitespace(bytes, cursor);
        let key = parse_string(bytes, cursor)?;
        skip_whitespace(bytes, cursor);
        if *cursor >= bytes.len() || bytes[*cursor] != ':' {
            return Err("expected ':' in object".into());
        }
        *cursor += 1;
        let value = parse_value(bytes, cursor)?;
        // A duplicate key is ambiguous, so it is rejected rather than
        // silently resolved to one of the two values.
        if fields.insert(key, value).is_some() {
            return Err("duplicate object key".into());
        }
        skip_whitespace(bytes, cursor);
        match bytes.get(*cursor) {
            Some(',') => *cursor += 1,
            Some('}') => {
                *cursor += 1;
                return Ok(Value::Object(fields));
            }
            _ => return Err("expected ',' or '}' in object".into()),
        }
    }
}

fn parse_array(bytes: &[char], cursor: &mut usize) -> Result<Value, String> {
    *cursor += 1; // consume '['
    let mut items = Vec::new();
    skip_whitespace(bytes, cursor);
    if *cursor < bytes.len() && bytes[*cursor] == ']' {
        *cursor += 1;
        return Ok(Value::Array(items));
    }
    loop {
        items.push(parse_value(bytes, cursor)?);
        skip_whitespace(bytes, cursor);
        match bytes.get(*cursor) {
            Some(',') => *cursor += 1,
            Some(']') => {
                *cursor += 1;
                return Ok(Value::Array(items));
            }
            _ => return Err("expected ',' or ']' in array".into()),
        }
    }
}

fn parse_string(bytes: &[char], cursor: &mut usize) -> Result<String, String> {
    if *cursor >= bytes.len() || bytes[*cursor] != '"' {
        return Err("expected a string".into());
    }
    *cursor += 1;
    let mut text = String::new();
    while *cursor < bytes.len() {
        match bytes[*cursor] {
            '"' => {
                *cursor += 1;
                return Ok(text);
            }
            '\\' => {
                *cursor += 1;
                let escape = *bytes.get(*cursor).ok_or("unterminated escape")?;
                *cursor += 1;
                match escape {
                    '"' => text.push('"'),
                    '\\' => text.push('\\'),
                    '/' => text.push('/'),
                    'b' => text.push('\u{08}'),
                    'f' => text.push('\u{0c}'),
                    'n' => text.push('\n'),
                    'r' => text.push('\r'),
                    't' => text.push('\t'),
                    'u' => {
                        let mut code = 0u32;
                        for _ in 0..4 {
                            let digit = *bytes.get(*cursor).ok_or("short \\u escape")?;
                            code = code * 16
                                + digit.to_digit(16).ok_or("invalid \\u escape")?;
                            *cursor += 1;
                        }
                        text.push(char::from_u32(code).ok_or("invalid code point")?);
                    }
                    other => return Err(format!("unsupported escape \\{other}")),
                }
            }
            other => {
                text.push(other);
                *cursor += 1;
            }
        }
    }
    Err("unterminated string".into())
}

fn parse_number(bytes: &[char], cursor: &mut usize) -> Result<Value, String> {
    let start = *cursor;
    if *cursor < bytes.len() && (bytes[*cursor] == '-' || bytes[*cursor] == '+') {
        *cursor += 1;
    }
    while *cursor < bytes.len()
        && (bytes[*cursor].is_ascii_digit()
            || bytes[*cursor] == '.'
            || bytes[*cursor] == 'e'
            || bytes[*cursor] == 'E'
            || bytes[*cursor] == '-'
            || bytes[*cursor] == '+')
    {
        *cursor += 1;
    }
    let text: String = bytes[start..*cursor].iter().collect();
    text.parse::<f64>()
        .map(Value::Number)
        .map_err(|_| format!("invalid number {text}"))
}
