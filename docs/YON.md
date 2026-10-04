# Running SESAME as a Yon Host

SESAME's `app/` directory is a Tachyon Yon project, passed to `ty` as the
project root (`ty serve app`). `ty` serves SESAME's HTTP API, and every
request starts the `sesame` engine for the length of that request. This guide
covers running it, configuring it, the reverse proxy it requires, the route
convention, its layers, signing in, errors, the command line and tests.

This is a developer preview. Read the throughput limits below before you put
traffic on it. [ADR 0007](adr/0007-sesame-ships-a-yon-host-project.md)
records why it works this way.

## What you need

- `ty` 26.36.01 built from Tachyon commit `a7ccbfff`. This is an unreleased
  development build: it carries Tachyon ADR 0095 (native Go code under a
  project's `server/packages/`), which no published Tachyon release has yet.
  SESAME is developed and gated against exactly this build; see
  [Continuous integration](#continuous-integration).
- For the [command line](#command-line) only: a `ty` that also carries
  Tachyon's `ty handler invoke` argument-binding fix (commit `d070022f`, not
  merged upstream yet). Without it, `ty handler invoke` passes no body,
  header or path values to a controller.
- Go, to build the engine from this repository.
- The pinned FYLO executable, and FYLO's `chex` helper on the `PATH` that `ty`
  starts with. A handler inherits that `PATH` and nothing else, so an engine
  that cannot find `chex` refuses to start
  (`FYLO runtime identity mismatch for dependencies.chex.available`). Put a
  directory that holds only `fylo` and `chex` on that `PATH`: `ty serve`,
  started by name, looks `ty` up on `PATH` again, so a directory that also
  holds another `ty` makes the server run that one instead (starting `ty` by
  its absolute path avoids it).
- A reverse proxy in front of `ty` that terminates TLS and limits request
  rates. It is not optional; see [Reverse proxy](#reverse-proxy-required).
- A Unix host; the Yon host is developed and tested on macOS. It has not
  been tested on Windows, where the Go package can end only the `sesame`
  process and not the FYLO runtime it started, so a request that gives up on
  an engine can leave the deployment held until that runtime exits
  ([ADR 0007](adr/0007-sesame-ships-a-yon-host-project.md)).

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

The answer names the new tenant (`tenant.tenant_id`) and the administrator
(`administrator.principal_id`). The administrator has no authenticator yet, so
nobody can sign in. Give it a password on the command line. The password is
read from an environment variable, never from an argument:

```bash
read -rs SESAME_PASSWORD && export SESAME_PASSWORD
sesame authn set-password --deployment /absolute/path/to/deployment \
  --principal-id prn_...
unset SESAME_PASSWORD
```

It answers `{"password_set":true}`. `--password-env NAME` reads the password
from another variable. The administrator can now sign in over HTTP (see
[Sign in](#sign-in)) and add a second factor through the self-service
authenticator routes.

## Configure

`ty` hands handlers one private configuration snapshot built from
`app/server/application.json`, an optional
`app/server/application-<profile>.json` selected with `YON_PROFILE`, and
`YON_` names from `app/.env`, the project root's `.env` (`app/.env.example`
lists them). Handlers see no other configuration. Their environment holds only
`PATH`, `LANG`, `LC_ALL` and `TMPDIR` (when set) from the process that started
`ty`, the snapshot in `YON_APPLICATION_JSON`, Tachyon's own
`YON_HANDLER_PROTOCOL`, and, under `ty serve`, the outgoing proxy variables
`ty` sets (`YON_OUTGOING_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and
their lowercase forms, `NODE_USE_ENV_PROXY`). There is no `HOME`. The working
directory is temporary, so every path must be absolute.

| Setting | `.env` name | Meaning |
| --- | --- | --- |
| `sesame.binary` | `YON_SESAME_BINARY` | Absolute path of the `sesame` executable. Required. |
| `sesame.deployment` | `YON_SESAME_DEPLOYMENT` | Absolute path of the deployment created by `sesame init`. Required. |
| `sesame.waitmilliseconds` | none: set it in a JSON file | How long a request waits while another request's engine owns the deployment. Default 5000, at most 20000. `.env` values are text, and this one must be a number. |
| `sesame.samlconsumerurls` | none: set it in a JSON file | Every `consumer_url` that `saml/login-start` accepts, matched exactly: absolute `https`, no fragment. Default empty, which refuses every SAML login start with `400 {"code":"redirect_not_allowed"}`. See [docs/yon/federation.md](yon/federation.md#allowed-redirect-targets). |
| `sesame.federationredirecturis` | none: set it in a JSON file | Every `redirect_uri` that `federation/login-start` accepts, with the same rules. Default empty (every OIDC federation login start is refused). |

Set the two paths either in `app/.env` or in a profile file:

```json
{
  "sesame": {
    "binary": "/opt/sesame/sesame",
    "deployment": "/var/lib/sesame/deployment"
  }
}
```

Do not set a value in both places: `ty` refuses a `.env` value that overwrites
a value from a JSON file. When a path is missing or relative, the wait is out
of range, or an allowlist entry is not an absolute `https` URL without a
fragment, every request that needs the engine answers
`500 {"code":"internal_error"}` (internally the host's `engine_not_configured`)
and the engine is not started.

## Run

```bash
ty serve app                     # development server, rebuilds on change
ty bundle app && ty start app    # build, then serve the built bundle
```

`server.host` and `server.port` in `app/server/application.json` choose the
address (`127.0.0.1:8080`). `ty` serves plain HTTP. Keep it on loopback,
behind the reverse proxy below. The `sesame` executable itself never opens a
port.

## Reverse proxy (required)

Never expose `ty` directly. Every request starts an engine, and only one
engine may own the deployment at a time, so a single anonymous client sending
requests in a loop can keep every other caller waiting and then refused with
`503` ([Throughput](#throughput)). Neither SESAME nor `ty` limits request
rates. A production or shared deployment must put a reverse proxy in front of
`ty` that:

1. terminates TLS, and is listed in `server.proxies` so that `ty` accepts its
   `X-Forwarded-Proto`; the public host name goes in `server.hosts`, and the
   proxy keeps the `Host` header;
2. limits requests per client IP address on every route that anyone may call
   or that verifies a credential:
   - `/api/v1/authn/*` (login steps; password and code guessing),
   - `/api/v1/session/verify` (session secret checks),
   - `/oidc/*` (token, introspection, revocation and the other standard
     endpoints),
   - `/api/v1/oidc/pushed-authorize`, `/api/v1/oidc/device-authorize` and
     `/api/v1/oidc/dpop-verify`,
   - `/api/v1/federation/login-*` and `/api/v1/saml/login-*`,
   - `/api/v1/scim/*` (bearer-token checks),
   - `/api/v1/system/*`;
3. limits the request body size (the standard endpoints refuse more than
   128 KiB themselves);
4. rewrites `/.well-known/openid-configuration` to
   `/oidc/openid-configuration`, because Tachyon cannot declare a route under
   `/.well-known` ([docs/yon/oidc.md](yon/oidc.md#discovery-at-well-knownopenid-configuration)).

An nginx sketch (adapt and test it; it is not part of the release gate):

```nginx
limit_req_zone $binary_remote_addr zone=sesame_public:10m rate=5r/s;

server {
    listen 443 ssl;
    server_name id.example;
    client_max_body_size 128k;
    limit_req_status 429;

    location = /.well-known/openid-configuration {
        limit_req zone=sesame_public burst=10 nodelay;
        proxy_pass http://127.0.0.1:8080/oidc/openid-configuration;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location ~ ^/(oidc/|api/v1/(authn|scim|system)/|api/v1/session/verify$|api/v1/oidc/(pushed-authorize|device-authorize|dpop-verify)$|api/v1/(federation|saml)/login-) {
        limit_req zone=sesame_public burst=10 nodelay;
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Choose the rates for your traffic; the engine serializes requests, so the sum
of all limits should stay well under the throughput below.

## Routes

Each machine operation family has one controller, and each operation is one
route:

```text
POST /api/v1/<family>/<operation>
```

An `_` in the operation name becomes `-`: `principal.create` is
`POST /api/v1/principal/create`. The request body is the operation's JSON
parameters; the answer is its JSON result. When a route takes a body, `ty`
refuses a field the route does not declare with `400` before SESAME runs; a
route that takes no body ignores one. `OPTIONS` on a route and
`GET /api.json` publish the schemas.

| Route | Operation | Who may call |
| --- | --- | --- |
| `POST /api/v1/system/ping` | `system.ping` | anyone |
| `POST /api/v1/system/version` | `system.version`, trimmed to `name`, `version` and `protocol_version` | anyone |
| `POST /api/v1/system/readiness` | `system.readiness` | anyone |
| `POST /api/v1/system/build` | `system.version` in full: also `commit`, `built_at`, `go_version`, `os`, `arch` and `operations` | an administrator |
| `POST /api/v1/system/metrics` | `system.metrics` | an administrator |
| `POST /api/v1/tenant/get` | `tenant.get` (by `tenant_id`) | an administrator of that tenant |

`system/metrics` reports the counters of the engine that answers it, and each
request starts its own engine. Its `requests_total` and `errors_total`
therefore count only that request's own engine calls (the version handshake,
`session.verify`, the administrator decision), and `uptime_seconds` is the age
of that engine. It is not a deployment-wide counter.

Every other family has its own page with its routes, who may call each one,
and why:

| Families | Page |
| --- | --- |
| `principal`, `role`, `grant`, `group`, `authorize` | [Directory and authorization routes](yon/directory.md) |
| `authn`, `authenticator`, `session`, `token` | [Authentication routes](yon/authn.md) |
| `oidc_client`, `oidc`, and the standard endpoints under `/oidc` | [OAuth and OpenID Connect routes](yon/oidc.md) |
| `federation`, `saml`, `scim` | [Federation, SAML and SCIM routes](yon/federation.md) |

`sesame init`, `tenant.bootstrap` and `admin.bootstrap` stay on the command
line. `federation.login_exchange` is never routed, because its answer carries
the identity provider's client secret.

`api/machine/v1/operations.json` records, under `http_coverage`, how each
operation is reached: `routed` with its routes, `standard_endpoint` with the
standard route that serves it, `command_line_only`, or
`not_routed_for_security`. Each routed or `standard_endpoint` entry also
records, under `access`, the guard every one of its routes declares
(`public`, `signed_in` or `administrator`; a method annotation wins over the
controller's). `go test ./test/contract` compares that record with the
`@PostRoute` and `@GetRoute` annotations in `app/server/controllers`, so a new
route, a new engine operation, a route with no guard or two guards, or a
changed guard fails the build until the manifest describes it.

## Layers

`app/server/` follows Tachyon's role folders, one layer each:

| Folder | Holds |
| --- | --- |
| `controllers/` | The SDK-facing endpoints. A route binds its typed input, names its engine operation, makes one service call and returns. Also the identity provider and the error handler. |
| `services/` | Every decision: the administrator role, tenant isolation, the recent sign-in policy and its table of privileged operations, passkey ownership, lookup forms, redirect allowlists, and the mapping of the caller's session onto engine parameters. |
| `helpers/` | Infrastructure with state that only services call: `EngineHelper` (the request's engine, its wait and `503`, and the actor) and `EngineSettingsHelper` (the `sesame` settings). |
| `utils/` | Stateless static functions any layer may call, such as `ProtocolErrorUtils` and `HeaderUtils`. |
| `stores/` | Nothing yet, on purpose. The `sesame` engine is SESAME's only FYLO store: one writer per FYLO root, with every security write in its hash-chained ledger. `ty`'s managed FYLO datasource has no transactions, so a Yon store would be a second writer outside the ledger. This waits for Samuel's decision. |

[ADR 0007](adr/0007-sesame-ships-a-yon-host-project.md#layers) names the
classes in each layer.

## Sign in

Sign in with the public `authn` routes, then send the session that
`authn/complete` issued in one header:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/authn/begin \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tnt_...","identifier_namespace":"email","identifier_value":"admin@acme.example"}'
# -> {"transaction_id":"txn_...",...}; then authn/verify-password with
#    {"transaction_id","password"}, and authn/complete with {"transaction_id"}
```

```text
Sesame-Session: <session_id>:<session_secret>
```

- No header, a malformed one, or an unknown, expired or revoked session, on a
  signed-in or administrator route: `401`, answered by `ty`'s route guard as
  plain text (`Sign in to call this route.`).
- A valid session on a route for administrators, when the session's principal
  is not allowed `sesame:administer` on `sesame:tenant` in its tenant: `403`,
  also plain text from the guard (`Your roles do not allow this route.`).
- A body that names a tenant other than the session's tenant:
  `403 {"code":"tenant_mismatch"}`.

Any role that allows `sesame:administer` on `sesame:tenant` makes its holders
tenant administrators over HTTP, including roles that allow `*` on `*`,
`sesame:*` on `*` or `sesame:*` on `sesame:*`. Treat the `sesame:` action and
resource names as reserved for SESAME and never grant a pattern that matches
them to anyone who should not administer the tenant.

Never put the secret in a URL. Sign out with `POST /api/v1/session/revoke`, or
revoke a session on the command line with `sesame session revoke`.

## Errors

An error answer comes from one of three places, with different shapes.

**SESAME's own refusals** (the engine and the host code in `app/server/`) answer
JSON `{"code":"<code>"}` through one code-to-status table:

| Status | When |
| --- | --- |
| `400` | The engine or the host refused the request as invalid: `invalid_request` (also the host's answer to `principal/get` naming `principal_id` together with `tenant_id` or an identifier field), `redirect_not_allowed` (a `login-start` URL not in the allowlist settings), and the engine's other validation codes. |
| `401` | `session_rejected`, `session_inactive`, `actor_session_invalid`, `provisioning_denied` (with `WWW-Authenticate: Bearer`). |
| `403` | `tenant_mismatch`, `actor_tenant_mismatch`, `access_denied`, `administrator_required` (an administrative call by a caller that is not an administrator, for example through `ty handler invoke`), `reauthentication_required` (a credential or privilege change with a session issued more than 10 minutes ago) and other refusals. |
| `404` | A named record does not exist (`principal_not_found`, ...). |
| `409` | A conflict (`identifier_conflict`, `stale_policy_version`, ...). |
| `503` | `engine_busy`, with `Retry-After: 1`: another request held the deployment, or the engine did not start, for the whole wait. Nothing ran; retry. |
| `500` | `internal_error`, including a missing or invalid configuration and an operation the host's public call path does not allow (the host's `operation_not_public`, a host programming error; the engine is not called). The cause is in the server log, never in the answer. |

**`ty`'s route guard** answers before any SESAME code runs, as
`text/plain`: `401 Sign in to call this route.` and
`403 Your roles do not allow this route.`. When the identity check itself
fails, the guard answers `500 Tachyon could not check who is signed in.`,
also plain text and without `Retry-After`. This is what a signed-in or
administrator route answers when the engine is busy: the identity check runs
first, finds the deployment held for the whole wait, and Tachyon cannot turn
that into a `503` (a Tachyon gap). Nothing ran, so the client may retry after
a short delay. Public routes, and signed-in routes called without a
`Sesame-Session` header, never start an engine for the identity check, so a
busy engine answers them `503 engine_busy` and `401` respectively.

**`ty`'s request checks** answer JSON in Tachyon's shape:
`400 {"error":"...","field":"...","part":"body"}` for a body that is not
valid JSON, does not fit the route's model, or has an undeclared field (the
message names the model, never the submitted value), and
`405 {"allow":"OPTIONS, POST","error":"..."}` for a method the route does not
answer.

The standard endpoints under `/oidc` answer OAuth error bodies
(`{"error":"invalid_client"}` and so on) instead; see
[docs/yon/oidc.md](yon/oidc.md).

## Throughput

Every request starts an engine, and only one engine may own a deployment at a
time. Requests therefore run one after another. On an Apple silicon laptop with
an empty deployment a public request takes about 0.24 s, and a signed-in
request starts two engines (the identity check and the route). Requests that
wait longer than `sesame.waitmilliseconds` get `503` (or `500` from the guard;
see [Errors](#errors)). Plan for a few requests per second, and rate-limit in
the [reverse proxy](#reverse-proxy-required).

## Command line

`ty handler invoke` runs one controller in the same environment as the server,
without the server. It needs a `ty` with the argument-binding fix (commit
`d070022f`, see [What you need](#what-you-need)); with `a7ccbfff` the
controller receives no body. It prints the answer as a Handler Protocol
envelope: `status`, `headers`, and the body in `body.data`.

Recommend it only to operators on a single-user host:

- Request headers are passed as `--header 'Name=value'` (not `Name: value`).
  A secret on the command line is visible to other local users while the
  command runs (`ps`) and may be kept in shell history.
- `ty` refuses a malformed `--header` and prints the whole rejected value,
  secret included, to the terminal.
- It does not run the identity check or the route guard (`@Public`,
  `@SignedIn`, `@Allow`). SESAME does not rely on them alone: a signed-in
  route still needs the `Sesame-Session` header (`401
  {"code":"session_rejected"}` without it), and every administrator route
  decides the `Administrator` role again inside its own call
  (`403 {"code":"administrator_required"}` for anyone else). Tenant checks and
  recent sign-in apply as over HTTP.

One example per access level (run from the repository root, with the
configuration above; `--project app` names the project root):

```bash
# anyone
ty handler invoke --project app server/controllers/SystemController.go \
  --route /api/v1/system/version --method post

# a signed-in principal, about itself
ty handler invoke --project app server/controllers/AuthorizeController.go \
  --route /api/v1/authorize/decide --method post \
  --header "Sesame-Session=$SESAME_SESSION" \
  --body '{"action":"doc:read","resource":"file:a"}'

# an administrator of the tenant
ty handler invoke --project app server/controllers/PrincipalController.go \
  --route /api/v1/principal/create --method post \
  --header "Sesame-Session=$SESAME_SESSION" \
  --body '{"tenant_id":"tnt_...","kind":"human","identifier_namespace":"email","identifier_value":"new@acme.example"}'
```

`SESAME_SESSION` holds `<session_id>:<session_secret>`. The administrator
example answers `200` with the new principal for an administrator's session
and `403 {"code":"administrator_required"}` for any other session.

On a shared host, or for anything a script runs unattended, use the `sesame`
operator CLI against the deployment instead.

## Tests

`ty test app --coverage` runs the units in `app/server/tests/`. Each case creates a
disposable deployment with `sesame init`. Test units do not see the parent
environment, so the setup finds `sesame` and `fylo` on `PATH`. Put the engine
built from this tree first:

```bash
go build -trimpath -o /tmp/sesame-test/sesame ./cmd/sesame
PATH=/tmp/sesame-test:$PATH ty test app --coverage
```

`ty test` calls controllers directly, so it cannot reach the route guard; the
guard's `401` and `403` answers are checked against `ty serve` by the
[smoke test](#smoke-test) below.

The Go SDK and the host errors have ordinary Go tests:

```bash
(cd app/server/packages && go test ./...)
```

### Smoke test

`tools/yon-smoke/smoke.sh` checks the running server end to end with `curl`.
It needs `ty`, `curl` and `jq` on `PATH`, an engine built from this tree and
the FYLO executable (with `chex` beside it or on `PATH`):

```bash
go build -trimpath -o /tmp/sesame-smoke/sesame ./cmd/sesame
tools/yon-smoke/smoke.sh /tmp/sesame-smoke/sesame /absolute/path/to/fylo
```

The second argument may be left out when `FYLO_BINARY` is set. The script
works only inside a new temporary directory and never changes the repository.
It creates a deployment with `sesame init`, bootstraps the tenants `acme` and
`globex` with an administrator each and an `acme` member on the command line,
copies `app/server/` and `app/package.json` into a project root next to it
with the deployment in that copy's `server/application.json`, starts
`ty serve` on that copy at a free port and signs everyone in through `authn/*`. It
then asserts exact status codes for each kind of route: public, signed in and
administrator; a missing or malformed session; a member on an administrator
route; another tenant's id in a body (`tenant_mismatch`) or in a reference
(`actor_tenant_mismatch`); an undeclared body field; the unrouted
`federation/login-exchange`; and `503` with `Retry-After` while a second
`sesame exec --loop` holds the deployment. Last, it checks that no password or
session secret reached the server log.

It prints one line per check and stops with `FAIL` and a non-zero exit at the
first failure. On every exit it stops the server and the engines and deletes
the temporary directory. Passwords and session secrets live only in files in
that directory, readable by you alone, and are never printed or passed as
command arguments.

## Continuous integration

GitHub Actions does not run the Yon tests yet. `ty test app --coverage` and
`ty bundle app` need a `ty` build that includes Tachyon ADR 0095 (native Go
code under a project's `server/packages/`) and the `ty handler invoke`
argument-binding fix, and no published Tachyon release carries both. Until one
does, the release gate runs them locally with the pinned development build
`a7ccbfff`, and CI runs everything else: the engine tests, the Go package
tests in `app/server/packages` and the `test/contract` checks that tie
`api/machine/v1/operations.json` to the routes in `app/server/controllers`.

When Tachyon publishes a release with both changes, CI gains a job that
installs that pinned release, builds the engine from this tree, puts it first
on `PATH` and runs `ty bundle app` and `ty test app --coverage`, and this section is
removed.
