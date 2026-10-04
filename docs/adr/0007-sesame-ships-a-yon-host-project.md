# ADR 0007: SESAME Ships a Yon Host Project

- Status: Accepted
- Date: 2026-10-04
- Accepted: 2026-10-04
- Amends: [ADR 0003](0003-headless-binary-and-client-contract.md)

## Context

ADR 0003 made SESAME a headless engine. The host application owns every
listener, TLS boundary, route and middleware chain, and talks to the engine
through a language SDK over stdin and stdout. SESAME shipped ten thin SDKs and
no host of its own, so every adopter wrote the same HTTP layer again.

The project now asks for one host that SESAME ships itself: the repository root
becomes a Tachyon **Yon** project, and the SDKs are replaced by Yon
controllers that answer HTTP requests and, once Tachyon binds arguments for
`ty handler invoke`, the command line.

The Yon Go runtime fixes several facts that shape this decision. They were
verified on `ty` 26.36.01 (`bf098bfc`):

- `ty` starts one operating-system process for each request, each identity
  check and each worker tick. No user code outlives its invocation. The
  deadline is 30 seconds and at most 16 invocations run at once.
- The handler environment is scrubbed to `PATH`, `TMPDIR` and the private
  `YON_APPLICATION_JSON` snapshot. There is no `HOME`. The working directory
  is a temporary directory, so paths must be absolute.
- Go handlers compile offline with the standard library only. Native code
  comes from one module under `server/packages/` (Tachyon ADR 0095).
- FYLO gives one process exclusive ownership of a root. A second engine
  started against the same deployment fails with `EROOTLOCKED`.

## Decision

### Layout

The engine module `github.com/d31ma/sesame` keeps its place at the root. The
Yon project lives beside it:

- `server/go.mod` is a sentinel module (`github.com/d31ma/sesame/server`). It
  keeps Yon sources out of the engine's `go test ./...` and `go vet ./...`;
  `ty` tolerates it.
- `server/packages/` is the native Go module
  `github.com/d31ma/sesame/server/packages`, standard library only. It holds
  the Go SDK (moved from `clients/go/sesame` with its history) and the `host`
  package of errors the Yon host raises.
- `go.work` at the root (`use .` and `use ./server/packages`) lets engine-module
  code that drives the engine through the SDK resolve it: `test/adversarial`,
  `internal/proving/qualification` and `examples/hostserver`. Building those
  three with `GOWORK=off` is unsupported. `cmd/sesame` does not import the SDK,
  so `go install github.com/d31ma/sesame/cmd/sesame@<version>` and
  `GOWORK=off go build ./cmd/sesame` keep working. Nothing in the engine's
  `cmd/` or production `internal/` code depends on `server/`.
- Controllers, services, models and roles follow Tachyon's role folders.
  `server/errors/` stays empty for the reason in "Tachyon gaps" below.

### Listener ownership (amends ADR 0003)

`ty` is the host application. It owns the listener, TLS termination or the
trusted proxy in front of it, routing and middleware. The `sesame` executable
still opens no port and still speaks only the NDJSON machine protocol on stdin
and stdout; `TestEngineOpensNoNetworkListener` stays a release gate. ADR 0003's
single-owner rule holds per invocation: one invocation owns one engine and one
FYLO root at a time.

### One engine per invocation, serialized, then 503

`EngineService` starts the engine the first time an invocation calls it and
reuses it for the rest of that invocation. The engine stops when the
invocation's process exits, because its stdin closes; no child outlives the
handler. When another engine owns the deployment, `EngineService` tries again
every 50 ms until `sesame.waitmilliseconds` (default 5000, at most 20000,
always under the 30 second deadline) has passed, and then fails with
`host.EngineBusyError`. An engine that has not finished starting when the wait
ends is stopped and answered the same way: the SDK's `StartWhenAvailable`
always wraps the context error when its context ends, and `EngineService` maps
`context.DeadlineExceeded` from its own wait to `EngineBusyError`. The answer is `503` with `Retry-After: 1` and
`{"code":"engine_busy"}`. Nothing ran, so the client may retry.

This is a developer-preview throughput ceiling. Measured on an Apple silicon
laptop with an empty deployment: a public request costs about 0.24 s, a
signed-in request costs two engine starts (identity check and route), and 20
simultaneous requests with a 1 second wait produced 6 answers and 14 `503`s.
A long-lived engine owned by `ty` would remove the ceiling; that needs a
Tachyon feature and is out of scope here.

### Who may call a route

The caller presents a SESAME session in one request header:

```text
Sesame-Session: <session_id>:<session_secret>
```

This reuses the session identifier and secret that `authn.complete` issues,
joined the way the reference host (`examples/hostserver`) joins them in its
cookie. No new token format or cryptography is introduced. A header, not a
cookie, carries it, so a browser never sends it implicitly and cross-site
request forgery cannot ride on it. The secret is never put in a path or query
string and never logged.

`SesameIdentityProvider` resolves the header with `session.verify`. A missing,
malformed, unknown, expired or revoked credential is no identity, so `ty`
answers `401`. A valid session is the user `<principal_id>`. It carries the
role `Administrator` only when `authorize.decide` allows action
`sesame:administer` on resource `sesame:tenant` in the session's tenant, asked
with the session so role conditions such as session assurance apply. The
administrator role that `admin.bootstrap` creates (`*` on `*`) satisfies it.
Every other session has no roles, so `@Allow(Administrator)` routes answer
`403`. When the engine is busy or fails, the identity check fails and `ty`
answers `500`: it never falls back to an anonymous or weaker identity.

The identity provider cannot see the request body, so it cannot enforce the
tenant boundary. Every tenant-bound route therefore runs through
`TenantCallService.Call(request, tenantID, call)`: it resolves the caller
again, refuses a body tenant that differs from the session tenant with
`host.TenantMismatchError` (`403`, `{"code":"tenant_mismatch"}`) before the
operation runs, and only then calls the engine. Cross-tenant administration is
not available over HTTP.

`system.ping`, `system.version` and `system.readiness` are `@Public`.
`system.metrics` is `@Allow(Administrator)`; it reports deployment-wide
counters of operation names and counts, with no identity data, so an
administrator of any tenant may read it.

### Operations that stay on the command line

`sesame init`, `tenant.bootstrap` and `admin.bootstrap` are never routed. They
create the trust root that the HTTP layer relies on, so they need local
operator access to the deployment.

### Routes and answers

Routes are RPC style, one controller per operation family:
`POST /api/v1/<family>/<operation>`, with `_` in the operation name written as
`-` (`principal.create` is `POST /api/v1/principal/create`). Requests and
results are typed models in `server/models/`; `ty` refuses undeclared fields
with `400`. Standards protocol endpoints keep their standard HTTP shapes.

`SesameErrorHandler` has one catch-all method. It reads the stable code of any
`host.CodedError` (the host errors and the SDK's `ProtocolError`) and maps it
through one code-to-status table: validation `400`, rejected or inactive
session `401`, denied or other tenant `403`, missing record `404`, conflict
`409`, busy engine `503`. A code the table does not know, an error without a
code and every `5xx` answer `{"code":"internal_error"}`. The engine's message
never reaches the client.

### Command-line invocation

`ty handler invoke server/controllers/<Family>Controller.go --route
/api/v1/<family>/<operation> --method post --body '<json>'` runs one
controller in the same scrubbed environment. It skips the server's identity
check, so it is an operator tool for someone who can already run the `sesame`
executable. Today it does not bind `@FromBody` arguments; until the Tachyon fix
ships, the `sesame` operator CLI remains the command-line interface.

### Audit

Every route that acts for a signed-in caller names that caller as the actor
of its engine requests, so the hash-chained security ledger records
`principal:<tenant>/<principal>/<session>` instead of `operator:machine`
(machine protocol RFC 0001, "Actor Attribution").

- **Where the actor comes from.** Only `CallerService.Resolve`, after SESAME
  has verified the `Sesame-Session` credential with `session.verify`, binds the
  caller to the invocation's `EngineService` (`ActAs`). No body, query or
  header field names an actor: a body that adds `actor` is refused with `400`
  as an undeclared field. Every caller-aware service (`TenantCallService`,
  `PrincipalTenantService`, `TenantRecordService`, `CallerCallService`) and
  every controller that resolves the caller itself therefore attributes all
  of its later engine calls, without passing the actor by hand.
- **What stays `operator:machine`.** Public routes (`authn/*`,
  `session/verify`, OIDC protocol endpoints, discovery, JWKS, SCIM with its
  bearer token, system routes) resolve no caller and send no actor. So do the
  command-line tools and any SDK use without `sesame.WithActor`.
  `standards.dispatch` never carries an actor: the Go client drops it there.
- **Fail closed.** The Go client sends `actor` only to an engine whose
  `system.version` lists it in `request_fields`. When a caller is bound and the
  engine does not list it, `EngineService` refuses the call
  (`sesame.IncompatibleEngineError`, `500`) rather than record the write as
  `operator:machine`.
- **Isolation by the engine.** The actor never grants access; the
  `@Allow(Administrator)` guard and the host's tenant checks stay. It adds one
  refusal: SESAME answers `actor_tenant_mismatch` (`403`) for any write into
  another tenant, and for any write aimed at another tenant's record whatever
  state that record is in, before anything is appended. Two administrator
  routes rely on it because SESAME cannot report the target's tenant first:
  `grant/revoke` and `session/revoke-by-id`. Grant and session IDs are random,
  and an unknown ID answers `404` in every tenant.
- **Evidence.** `server/tests/ActorAttributionTest.go` performs writes over the
  controllers, closes the invocation's engine, and reads the actor of each
  event from the FYLO `sesame-security-events` collection with
  `fylo sql ... --root <deployment>/fylo-root`.
- **One invocation, one caller.** A `ty` invocation serves one request, so the
  bound caller lives exactly as long as that request. A test that drives
  several requests through one `EngineService` rebinds the caller each time it
  resolves one, and must close the engine before the next invocation opens
  the deployment.

## Tachyon gaps

Each gap has a workaround in this repository and a repro in the swarm notes.

1. An `@IdentityProvider` gets no injected fields: both `@NeedsAll` and
   per-field `@Needs` arrive nil under `ty serve`. The provider builds its
   services itself.
2. The `@IdentityProvider` unit does not compose `server/errors/`, so an error
   type there is undefined in the identity check. Host errors live in
   `server/packages/host`.
3. An `@HandlesError` parameter typed from a `server/packages` import does not
   compile (the generated `errors.go` lacks the import). The handler takes the
   catch-all `error` and reads `host.CodedError`.
4. Any Go `@Service` with `@OnStop` makes every Go test unit fail with
   `TY2015` ("Go route XTest.POST is not declared"). The engine closes on
   process exit instead of in a stop hook.
5. `ty test` units receive neither `YON_APPLICATION_JSON` nor variables from
   the parent environment except `PATH` and `TMPDIR`. The test setup finds
   `sesame` and `fylo` on `PATH` and writes the snapshot itself.
6. `ty handler invoke` does not bind arguments (decision recorded in the
   project brief; a Tachyon change is in progress).
7. `ty serve` kept serving the previous identity provider after a source change
   until it restarted.

## Consequences

- SESAME ships a runnable host. Adopters configure two absolute paths and run
  `ty serve`.
- The Go SDK changes its import path to
  `github.com/d31ma/sesame/server/packages/sesame`; release notes must say so.
- Every request pays an engine start. The preview is not for high request
  rates.
- The project root's `.env` belongs to `ty` (it accepts only `YON_` names), so
  the `sesame init` example file is `sesame.env.example`.
- Tachyon's build-time design rules (one decision per helper, no unused public
  methods, no repeated literals) apply to everything under `server/` except
  `server/packages/`.

## Rejected alternatives

- **A long-lived engine inside a Yon handler.** No user process outlives an
  invocation, so it cannot be built on today's `ty`.
- **One engine per worker or per server.** Same reason; also refused by FYLO's
  single-owner root.
- **A bearer token in `Authorization`.** RFC 6750 tokens cannot contain `:`, and
  encoding the pair differently would invent a format.
- **A cookie.** It is ambient authority and would need cross-site request
  forgery defenses that a programmatic API does not otherwise need.
- **Keeping `clients/go` in the engine module.** Yon handlers can import native
  Go code only from `server/packages`.
