# Running SESAME as a Yon Host

SESAME's repository root is also a Tachyon Yon project. `ty` serves SESAME's
HTTP API, and every request starts the `sesame` engine for the length of that
request. This guide covers running it, configuring it, the route convention,
signing in, errors, the command line and tests.

This is a developer preview. Read the throughput limits below before you put
traffic on it. [ADR 0007](adr/0007-sesame-ships-a-yon-host-project.md)
records why it works this way.

## What you need

- `ty` 26.36.01 or later on `PATH`.
- Go, to build the engine from this repository.
- The pinned FYLO executable, and FYLO's `chex` helper on the `PATH` that `ty`
  starts with. A handler inherits that `PATH` and nothing else, so an engine
  that cannot find `chex` refuses to start
  (`FYLO runtime identity mismatch for dependencies.chex.available`).

## Prepare an engine and a deployment

```bash
go build -trimpath -o /absolute/path/to/sesame ./cmd/sesame
cp sesame.env.example sesame.env        # edit SESAME_DEPLOYMENT and FYLO_BINARY
/absolute/path/to/sesame init --env-file sesame.env
```

Create the first tenant and its administrator on the command line. These
operations are never available over HTTP:

```bash
sesame admin bootstrap --deployment /absolute/path/to/deployment --name acme \
  --identifier-namespace email --identifier-value admin@acme.example
```

## Configure

`ty` hands handlers one private configuration snapshot built from
`server/application.json`, an optional `server/application-<profile>.json`
selected with `YON_PROFILE`, and `YON_` names from `.env` at the project root.
Handlers do not see any other environment variable, and their working directory
is temporary, so both paths must be absolute.

| Setting | `.env` name | Meaning |
| --- | --- | --- |
| `sesame.binary` | `YON_SESAME_BINARY` | Absolute path of the `sesame` executable. Required. |
| `sesame.deployment` | `YON_SESAME_DEPLOYMENT` | Absolute path of the deployment created by `sesame init`. Required. |
| `sesame.waitmilliseconds` | none: set it in a JSON file | How long a request waits while another request's engine owns the deployment. Default 5000, at most 20000. `.env` values are text, and this one must be a number. |

Set the two paths either in `.env` (copy `.env.example`) or in a profile file:

```json
{
  "sesame": {
    "binary": "/opt/sesame/sesame",
    "deployment": "/var/lib/sesame/deployment"
  }
}
```

Do not set a value in both places: `ty` refuses a `.env` value that overwrites
a value from a JSON file. When a path is missing or relative, or the wait is
out of range, every request that needs the engine answers `500` and the engine
is not started.

## Run

```bash
ty serve                 # development server, rebuilds on change
ty bundle && ty start    # build, then serve the built bundle
```

`server.host` and `server.port` in `server/application.json` choose the
address (`127.0.0.1:8080`). `ty` serves plain HTTP; put TLS in a reverse proxy
and list it in `server.proxies`. The `sesame` executable itself never opens a
port.

## Routes

Each machine operation family has one controller, and each operation is one
route:

```text
POST /api/v1/<family>/<operation>
```

An `_` in the operation name becomes `-`: `principal.create` is
`POST /api/v1/principal/create`. The request body is the operation's JSON
parameters; the answer is its JSON result. `ty` refuses a body with a field the
route does not declare (`400`). `OPTIONS` on a route and `GET /api.json`
publish the schemas.

| Route | Operation | Who may call |
| --- | --- | --- |
| `POST /api/v1/system/ping` | `system.ping` | anyone |
| `POST /api/v1/system/version` | `system.version` | anyone |
| `POST /api/v1/system/readiness` | `system.readiness` | anyone |
| `POST /api/v1/system/metrics` | `system.metrics` | an administrator |
| `POST /api/v1/tenant/get` | `tenant.get` (by `tenant_id`) | an administrator of that tenant |

`sesame init`, `tenant.bootstrap` and `admin.bootstrap` stay on the command
line.

## Sign in

Send the session that `authn.complete` issued in one header:

```text
Sesame-Session: <session_id>:<session_secret>
```

- No header, a malformed one, or an unknown, expired or revoked session: `401`.
- A valid session on a route for administrators, when the session's principal
  is not allowed `sesame:administer` on `sesame:tenant` in its tenant: `403`.
- A body that names a tenant other than the session's tenant:
  `403 {"code":"tenant_mismatch"}`.

Never put the secret in a URL. Revoke the session with `sesame session revoke` when you are done with it.

## Errors

Errors answer `{"code":"<code>"}`:

| Status | When |
| --- | --- |
| `400` | The engine refused the request as invalid. |
| `401` | `session_rejected`, `session_inactive`. |
| `403` | `tenant_mismatch`, `access_denied` and other refusals. |
| `404` | A named record does not exist (`principal_not_found`, ...). |
| `409` | A conflict (`identifier_conflict`, `stale_policy_version`, ...). |
| `503` | `engine_busy`, with `Retry-After: 1`. Nothing ran; retry. |
| `500` | `internal_error`. The cause is in the server log, never in the answer. |

## Throughput

Every request starts an engine, and only one engine may own a deployment at a
time. Requests therefore run one after another. On an Apple silicon laptop with
an empty deployment a public request takes about 0.24 s, and a signed-in
request starts two engines (the identity check and the route). Requests that
wait longer than `sesame.waitmilliseconds` get `503`. Plan for a few requests
per second.

## Command line

`ty handler invoke` runs one controller in the same environment as the server:

```bash
ty handler invoke server/controllers/SystemController.go \
  --route /api/v1/system/version --method post
```

It skips the server's identity check, so treat it as an operator tool. It does
not bind request bodies to `@FromBody` arguments yet; until Tachyon ships that,
use the `sesame` operator CLI for operations that take parameters.

## Tests

`ty test --coverage` runs the units in `server/tests/`. Each case creates a
disposable deployment with `sesame init`. Test units do not see the parent
environment, so the setup finds `sesame` and `fylo` on `PATH`. Put the engine
built from this tree first:

```bash
go build -trimpath -o /tmp/sesame-test/sesame ./cmd/sesame
PATH=/tmp/sesame-test:$PATH ty test --coverage
```

The Go SDK and the host errors have ordinary Go tests:

```bash
(cd server/packages && go test ./...)
```
