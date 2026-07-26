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

Messages may change. SDKs must branch on codes, not messages.

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
