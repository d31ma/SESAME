# RFC 0001: Machine Protocol v1

- Status: Implemented for system operations
- Date: 2026-07-23

## Purpose

The local machine protocol lets a language SDK own one SESAME subprocess
without linking internal Go packages. It is for a process that exclusively owns
its configured SESAME data root. Another SDK client, host replica, or application
must not start a second writer against that root.

The host application owns its network server. SESAME never listens on an
application port. Future SDK framework adapters will preserve OAuth/OIDC wire
formats at the host's public routes while forwarding a bounded, versioned
request representation to the SESAME subprocess for protocol processing.

## Transport

- command: `sesame exec --loop`;
- input: UTF-8 NDJSON on stdin;
- output: UTF-8 NDJSON protocol frames on stdout;
- diagnostics: stderr only;
- maximum frame: 1 MiB;
- one response per accepted request;
- requests are processed serially in input order.

EOF requests graceful shutdown. A frame larger than the limit receives
`frame_too_large` and terminates the loop because the next trustworthy frame
boundary is unknown.

## Request

```json
{
  "protocol_version": "1",
  "request_id": "caller-generated-id",
  "operation": "system.ping",
  "parameters": {}
}
```

`request_id` is 1-128 ASCII letters, digits, dots, underscores, colons, or
hyphens. It is correlation data, not a credential or idempotency key.

Unknown and duplicate object fields are rejected. Scaffold system operations
accept an empty parameter object only.

A request may also carry the optional `actor` field described under
[Actor Attribution](#actor-attribution). It is the only optional envelope
field, and an engine that does not list it in `system.version`
`request_fields` rejects it as an unknown field.

## Responses

Success:

```json
{
  "protocol_version": "1",
  "request_id": "caller-generated-id",
  "ok": true,
  "result": {}
}
```

Failure:

```json
{
  "protocol_version": "1",
  "request_id": "caller-generated-id",
  "ok": false,
  "error": {
    "code": "invalid_request",
    "message": "safe human-readable summary",
    "retryable": false
  }
}
```

Stable scaffold error codes are:

- `frame_too_large`;
- `invalid_json`;
- `invalid_request`;
- `unsupported_protocol`;
- `operation_not_found`;
- `internal_error`.

Operations add their own stable codes. `api/schema/machine-v1.schema.json`
lists every code the engine can return, and a test in the machine adapter
parses the code constants so the list cannot drift from the engine.

Messages may change. SDKs must branch on codes, not messages.

## Actor Attribution

- Status: Implemented (engine). The Go SDK option is a later slice.
- Date: 2026-10-04

### Problem

Every machine-protocol write records the actor `operator:machine`. When a
host serves SESAME operations over HTTP on behalf of a signed-in principal,
the audit ledger cannot say who acted.

### Wire shape

```json
{
  "protocol_version": "1",
  "request_id": "caller-generated-id",
  "operation": "principal.suspend",
  "parameters": {"principal_id": "prn_..."},
  "actor": {
    "tenant_id": "tnt_...",
    "principal_id": "prn_...",
    "session_id": "ses_..."
  }
}
```

- `actor` is optional. When it is absent the engine behaves exactly as
  before, byte for byte, and records `operator:machine`.
- All three members are required and must be SESAME identifiers. Unknown
  members, `null`, any other JSON type, and an actor longer than 512
  serialized bytes are refused with `invalid_actor`. Duplicate members are
  refused with `invalid_request`, like any duplicate field in a frame.
- No secret travels in `actor`.

### Negotiation

`system.version` returns `request_fields`, the optional envelope fields this
engine accepts. An engine that supports attribution lists `"actor"`. Older
engines omit `request_fields` and reject `actor` as an unknown field, so a
client sends `actor` only after it has seen `"actor"` in that list. Clients
decode `system.version` results leniently, so the new result field does not
affect older clients. Protocol v1 is unchanged; no version bump is needed.

### Engine checks

After the operation is found, the engine checks the actor in this order and
stops at the first failure. A refusal is returned before the operation runs.

1. Shape: `invalid_actor`.
2. `standards.dispatch` refuses an actor with `invalid_actor`. Standards
   endpoints authenticate their caller by protocol (client credentials,
   codes, tokens), not by a SESAME session.
3. Without a FYLO root the engine cannot check the session:
   `storage_not_configured`.
4. Live-session cross-check: the session must exist, be active (not expired
   or revoked), belong to that principal in that tenant, and the principal
   must be active. Otherwise `actor_session_invalid`.
5. Tenant consistency: every event the operation records must belong to the
   actor's tenant. The check sits in front of the security ledger, so it
   covers operations that name no tenant (`principal.suspend`,
   `grant.revoke`, `session.revoke`, ...). A write into another tenant is
   refused with `actor_tenant_mismatch` before anything is appended.

All three codes are not retryable.

### Recorded actor

An attributed event records
`principal:<tenant_id>/<principal_id>/<session_id>` as its actor, beside the
event's own `tenant_id`. The text cannot collide with `operator:*` actors.
Session IDs are public handles, not secrets.

### Attribution is not authorization

The actor changes who is recorded, never what is allowed. It can only make
the engine refuse a request; it never permits a request the same request
without an actor would be refused. Decisions, session verification, and
every other result are computed exactly as without an actor. Reads record no
event, so an actor on a read is checked (steps 1 to 4) and has no other
effect. The host still enforces access at its own route boundary (for
example, with `authorize.decide`).

### Decision: cross-check the actor against a live session

The pipe-holding host is trusted: it can already call any operation as
`operator:machine`, so no check here stops a malicious host. The question is
whether the engine should catch a host that is mistaken. It should:

- the check is a lookup by session ID in state the engine already holds, with
  no new cryptography and no secret in the frame;
- it stops a host defect (a stale cache, a mixed-up caller, a revoked or
  suspended principal) from writing a false name into an append-only,
  hash-chained ledger, where it can never be corrected;
- revocation and suspension take effect for attribution immediately.

The engine does not re-verify the session secret. The host proved it with
`session.verify` for the same HTTP request; asking for it again would put a
bearer secret in every frame without adding a trust boundary.

## Versioning

Protocol v1 uses exact major-version negotiation. Additive operations and
result fields may be introduced only after unknown-field behavior for responses
is tested in every supported SDK. A breaking framing or semantic change requires
a new major protocol version and a documented overlap/deprecation window.

## Cancellation and Retries

The scaffold serializes one request at a time. Canceling a Go SDK request stops
the owned local process because v1 has no safe in-band cancellation operation.
Callers must start a new client afterward.

No operation is retryable by default. Future mutating operations must define
idempotency behavior before their SDK method is published.

## Security

- The machine channel is local and inherits the child process permissions.
- The processor reads caller-supplied stdin/stdout streams and never opens a
  network listener.
- SDK arguments are passed directly to process APIs, never through a shell.
- Request and response sizes are bounded.
- Invalid requests never select an authentication or authorization transition.
- Machine stdout cannot contain logs or human-oriented banners.
- A shim may manage transport and lifecycle but may not implement security
  decisions.
- An attributed actor is checked against a live session and can only be
  recorded on its own tenant's events; it never grants access.
