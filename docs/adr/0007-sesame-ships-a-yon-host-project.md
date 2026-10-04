# ADR 0007: SESAME Ships a Yon Host Project

- Status: Accepted
- Date: 2026-10-04
- Accepted: 2026-10-04
- Revised: 2026-10-04, after the security and quality reviews (administrator
  re-decision, recent sign-in for privileged changes, error shapes, metrics
  scope, command line, reverse proxy, Tachyon gaps)
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
- The handler environment is scrubbed. It keeps `PATH`, `LANG`, `LC_ALL` and
  `TMPDIR` from the process that started `ty`, and adds the private
  `YON_APPLICATION_JSON` snapshot and `YON_HANDLER_PROTOCOL`; under `ty serve`
  it also carries the outgoing proxy variables `ty` sets
  (`YON_OUTGOING_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, their
  lowercase forms and `NODE_USE_ENV_PROXY`). There is no `HOME` and no other
  parent variable. The working directory is a temporary directory, so paths
  must be absolute. The engine inherits this environment.
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
`context.DeadlineExceeded` from its own wait to `EngineBusyError`. The answer
is `503` with `Retry-After: 1` and `{"code":"engine_busy"}`. Nothing ran, so
the client may retry.

The Go package starts the engine as the leader of its own process group, so a
request that gives up on a start, a cancelled call, or a `Close` that has to
kill the engine ends and reaps the engine's FYLO runtime too. This holds on
Unix only. On Windows (`server/packages/sesame/process_group_other.go`) the
package kills only the `sesame` process, and an engine killed that way can
leave its FYLO child holding the deployment until that child exits, so later
requests answer `503` meanwhile. The Yon host has not been tested on Windows.

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
answers `500` with the plain-text body `Tachyon could not check who is signed
in.` and no `Retry-After`: an identity provider cannot choose its status
(Tachyon gap 12 below), so signed-in and administrator routes cannot answer
`503` for a busy engine the way public routes do. It never falls back to an
anonymous or weaker identity.

The `sesame:` action and resource names are reserved for this check. Any role
whose permissions match `sesame:administer` on `sesame:tenant` (for example
`*` on `*`, `sesame:*` on `*`, or `sesame:*` on `sesame:*`) makes its holders
tenant administrators over HTTP, conditions permitting. SESAME does not refuse
such grants, because the engine has no notion of the Yon host; operators must
treat a wildcard role as an administrator role. Restricting the reserved
namespace in the engine is future work.

The identity provider cannot see the request body, so it cannot enforce the
tenant boundary. Every administrative route therefore runs through one
service, `TenantCallService`: `Call(request, tenantID, call)` for a body that
names a tenant, `Load` and `CallOwned` for a record that must be loaded first
to learn its tenant, and `CallAsAdministrator` for a route that names no
tenant. Each of them resolves the caller again, **decides the
`Administrator` role again inside the route's own invocation**
(`host.AdministratorRequiredError`, `403 administrator_required`), refuses a
tenant that differs from the session tenant with `host.TenantMismatchError`
(`403 tenant_mismatch`), and only then calls the engine. The route guard
alone is therefore never the only check: a caller that reaches a controller
without it, through `ty handler invoke`, is refused the same way.
`PrincipalTenantService` delegates to `TenantCallService` for principals
addressed only by id. Self-service routes bind the caller's own session
instead of asking for the role (`CallAsCaller`, `LoadAsCaller`, or the
caller resolved in the controller). Cross-tenant administration is not available over HTTP.

An `EngineCall` marked `Privileged` (credential and privilege changes:
`authenticator/set-password-for-principal`,
`authenticator/passkey-remove-for-principal`, `grant/create`,
`group/member-add`, `principal/suspend`, `oidc-client/rotate-secret`, the
self-service authenticator changes, and the federation, SAML and SCIM
credential routes listed in docs/yon/federation.md) also needs a session
issued within the last 10 minutes (`RecentSignInService`,
`403 reauthentication_required`). Revocations and other changes that only
reduce access do not. The residual risk is recorded in
the threat model: a session stolen within its first 10 minutes passes, and no
route asks for the current password, because the engine has no
reauthentication primitive.

`system.ping`, `system.version` and `system.readiness` are `@Public`; the
public `system.version` answer is trimmed to `name`, `version` and
`protocol_version`. `system/build` (the full `system.version` answer: commit,
build time, Go version, platform and operation list) and `system.metrics` are
`@Allow(Administrator)` and resolve the caller to decide the role again.
`system.metrics` reports the counters of the engine that answers it, and that
engine lives for one request: its counts cover only that request's own engine
calls (handshake, `session.verify`, `authorize.decide`), never the deployment.
It holds no identity data, so an administrator of any tenant may read it.
Deployment-wide metrics need a long-lived engine (see the throughput ceiling
above).

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

Two kinds of answer never pass through this handler, and clients must expect
their shapes: `ty`'s route guard answers `401`, `403` and a failed identity
check (`500`) as plain text, and `ty`'s request checks answer `400` as
`{"error","field","part"}` and `405` as `{"allow","error"}`.

### Command-line invocation

`ty handler invoke server/controllers/<Family>Controller.go --route
/api/v1/<family>/<operation> --method post --body '<json>' --header
'Sesame-Session=<session_id>:<session_secret>'` runs one controller in the
same scrubbed environment. Binding the body, headers and path values needs
Tachyon's argument-binding fix (`d070022f`, not merged upstream yet); the
`bf098bfc` build passes none of them.

It skips the server's identity check and the route guard. SESAME does not
depend on them: a signed-in route still needs the `Sesame-Session` header
(`401 session_rejected`), and every administrative call decides the
`Administrator` role again inside the service (`403 administrator_required`),
so the command line grants nothing the HTTP API would refuse. It is still an
operator tool, recommended only on a single-user host: a session secret passed
with `--header` is visible to other local users in the process list, and `ty`
echoes a malformed `--header` value, secret included, in its error. The
`sesame` operator CLI, which reads secrets from environment variables, stays
the command-line interface for shared hosts and scripts.

### Audit

Every route that acts for a signed-in caller names that caller as the actor
of its engine requests, so the hash-chained security ledger records
`principal:<tenant>/<principal>/<session>` instead of `operator:machine`
(machine protocol RFC 0001, "Actor Attribution").

- **Where the actor comes from.** Only `CallerService.Resolve`, after SESAME
  has verified the `Sesame-Session` credential with `session.verify`, binds the
  caller to the invocation's `EngineService` (`ActAs`). No body, query or
  header field names an actor: a body that adds `actor` is refused with `400`
  as an undeclared field. Every caller-aware service (`TenantCallService`, and
  `PrincipalTenantService`, which delegates to it) and every controller that
  resolves the caller itself therefore attributes all of its later engine
  calls, without passing the actor by hand. The former `TenantRecordService`
  and `CallerCallService` were merged into `TenantCallService`.
- **What stays `operator:machine`.** Public routes (`authn/*`,
  `session/verify`, OIDC protocol endpoints, discovery, JWKS, SCIM with its
  bearer token, and the public system routes `ping`, `version` and
  `readiness`) resolve no caller and send no actor. So do the command-line
  tools and any SDK use without `sesame.WithActor`. `system/metrics` and
  `system/build` resolve the caller to decide the role, so their engine calls
  carry the actor, but they only read and record nothing.
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

Each gap has a workaround in this repository. They are collected, with
proposed fixes, in a draft Tachyon feature request that has not been filed.

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
6. `ty handler invoke` does not bind arguments in `bf098bfc`. The fix
   (`d070022f`) is ready but not merged upstream.
7. `ty serve` kept serving the previous identity provider after a source change
   until it restarted.
8. No user process outlives an invocation, and Yon has no managed long-lived
   process resource (as `ty` already has for the FYLO datasource). Hence one
   engine per request, serialized, and the throughput ceiling above.
9. A route segment may use only lowercase letters, digits and hyphens, so
   `/.well-known/openid-configuration` cannot be declared (`TY2015`).
   Discovery is served at `/oidc/openid-configuration` and the reverse proxy
   rewrites the well-known path.
10. An `@IdentityProvider` cannot pass the identity it resolved to the route,
    so routes verify the session again (one more engine call per guarded
    request).
11. An `@IdentityProvider` cannot see which route it guards, so every
    signed-in request pays the administrator decision, even on routes that
    ignore roles.
12. An `@IdentityProvider` failure is always a plain-text `500` ("Tachyon could
    not check who is signed in."), without `Retry-After`. A busy engine during
    the identity check therefore answers `500`, not `503`, on signed-in and
    administrator routes.
13. `ty test` cannot exercise the route guard, so the guard's `401`, `403` and
    `500` answers are only testable end to end against `ty serve`. The host
    decides the role again in the service, so `ty test` covers that refusal.
14. Go test units cannot share helpers: a helper file in `server/tests` is not
    composed (`TY2004`), `@Test` takes one setup (`TY1308`), and a top-level
    function in a test file is refused (`TY1310`). Every fixture lives on
    `SesameTestSetup`, and a type only tests need lives in `server/models`
    (see "Test seams" below).
15. The plain-English name check splits initialisms wrongly: `IDs` becomes the
    non-word `ds`, and `URLs`/`URIs` become `ur` (`TY1328`). Fields are named
    `CredentialIdentifiers`, `SamlConsumerAddresses` and so on; JSON keys are
    unchanged.
16. Yon has no rate-limiting facility for public routes. A reverse proxy must
    limit them (docs/YON.md).
17. A route added while `ty serve` runs answers `405` until the server
    restarts.
18. The duplicate-code check (`TY1315`) flags thin controllers that share a
    dependency-and-create shape, and makes "one typed route per operation"
    impossible for families of about six or more uniform one-statement
    delegations. SESAME sets `duplication.check` to `false` (the Tachyon
    ADR 0064 migration switch); any duplicate other than a one-statement route
    delegation is still a defect.
19. Go test assertions have no `Assert.IsFalse`.
20. A native `*http.Response` with an empty body from a Go route answers `500`;
    the standard endpoints type an empty body `text/plain`.
21. Yon Go files have no package clause, so `gofmt` and `go/parser` cannot read
    them. And no installable `ty` release carries Tachyon ADR 0095 and the
    invoke fix, so GitHub Actions has no Yon job (docs/YON.md).
22. `ty migrate check` disagrees with `ty bundle`: it reports "no provider
    declared" for every controller and service, flags `@ErrorHandler`, and
    scans the nested `website/` project.
23. `ty handler invoke --header` takes `name=value`, not `Name: value`, and a
    rejected value is echoed verbatim, secret included.
24. `GET /api.json` publishes every model, including internal ones such as
    `EngineCall`, `EngineSettings`, `ApplicationSnapshot` and
    `SecurityEventActor`.
25. `ty serve` starts `ty` again by name from `PATH`. A `PATH` that puts a
    directory holding an older `ty` first (for example the directory that
    holds `fylo` and `chex`) runs that `ty` instead, which fails with
    `TY1002`. Operators put a directory holding only `fylo` and `chex` on
    `PATH`.

## Test seams

Two pieces of production code exist for tests. Both are kept deliberately:

- `server/models/SecurityEventActor.go` (`{"actor"}`) is used only by
  `server/tests/ActorAttributionTest.go`, which reads the actor of each ledger
  event with `fylo sql`. It lives in `server/models` because Tachyon composes
  no type declared in `server/tests` (gap 14). No route takes or returns it; it
  holds no secret, and its only exposure is the `/api.json` listing (gap 24).
- `RecentSignInService.clockShift` is a duration added to the current time
  before the 10-minute recent sign-in check. No configuration sets it, so it
  is zero in every production instance. Tests set it to act as if a session
  was issued more than 10 minutes ago, because the engine sets `issued_at`
  and the Yon tests cannot move the engine's clock. A configurable clock would
  be a production setting able to weaken the check; this field is not.

## Consequences

- SESAME ships a runnable host. Adopters configure two absolute paths and run
  `ty serve`.
- The Go SDK changes its import path to
  `github.com/d31ma/sesame/server/packages/sesame`; release notes must say so.
- Every request pays an engine start. The preview is not for high request
  rates, and one anonymous client can starve every other caller. A
  TLS-terminating, rate-limiting reverse proxy in front of `ty` is therefore
  required, never optional (docs/YON.md lists the paths to limit).
- Signed-in and administrator routes answer a busy engine with `500`, not
  `503`, until Tachyon lets an identity provider choose its status (gap 12).
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
