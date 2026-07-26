<p align="center">
  <a href="https://github.com/d31ma/sesame/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat" alt="Apache-2.0"></a>
  <img src="https://img.shields.io/badge/go-1.26-00ADD8?style=flat&logo=go&logoColor=white" alt="Go 1.26">
  <img src="https://img.shields.io/badge/protocol-v1-8b7cf6?style=flat" alt="machine protocol v1">
  <img src="https://img.shields.io/badge/direct%20dependencies-1-success?style=flat" alt="one direct dependency">
  <img src="https://img.shields.io/badge/status-developer%20preview-f59e0b?style=flat" alt="developer preview">
</p>

<h1 align="center">SESAME</h1>

<p align="center">
  A headless authentication and authorization engine for self-hosted
  applications, backed by <a href="https://fylo.del.ma">FYLO</a>.<br/>
  It opens no port. Your application owns every listener; SESAME owns every
  security decision.
</p>

<p align="center">
  <a href="https://sesame.del.ma">Website</a>
  ·
  <a href="https://sesame.del.ma/docs">Docs</a>
  ·
  <a href="api/machine/v1/README.md">Protocol</a>
  ·
  <a href="docs/PROJECT_PLAN.md">Project plan</a>
  ·
  <a href="https://github.com/d31ma/sesame/issues">Issues</a>
</p>

---

Most identity servers ask you to run one more thing on the network and trust it
with your users. SESAME is a binary your application starts. It speaks NDJSON
over stdin and stdout, has no listener to expose, no admin console to leak, and
no origin to be confused about.

```text
your application  →  SDK shim  →  sesame engine  →  FYLO
 owns every route     one file     every decision    documents are truth
```

That architecture is enforced rather than documented: a test inspects the
linked dependency graph of the shipped binary and fails the build if an HTTP
package, a template engine, or an unexpected module ever appears in it.

## Quick start

```bash
go install github.com/d31ma/sesame/cmd/sesame@latest

# Name the deployment once. Every sesame command reads it, and so does the
# engine your application starts, so no path is repeated on a command line.
export SESAME_DEPLOYMENT=./deploy

# A deployment holds validated configuration and the key boundary: an ES256
# signing key, a sealed-secrets key, and a snapshot key, written 0600 outside
# every FYLO document. init records the FYLO path in config.json, so it is a
# flag here rather than a variable every later command would have to ignore.
sesame init --fylo-binary /path/to/fylo \
  --issuer https://id.example.com

sesame doctor
```

Your application needs one more variable — where the engine binary is — and
then no path appears in application code:

```bash
export SESAME_BINARY=/usr/local/bin/sesame
```

```python
from sesame import Client

with Client() as client:
    decision = client.decide({
        "tenant_id": tenant_id,
        "principal_id": principal_id,
        "action": "doc:read",
        "resource": "project:alpha",
    })
    # {"decision": "deny", "reason_code": "deny_no_grant", "policy_version": 4}
```

Default deny: without a matching grant, that is the answer. See
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the environment variables
and the key boundary, and [sesame.del.ma/docs](https://sesame.del.ma/docs) for
working call sequences in all ten languages.

## What is built

| Area | Implemented |
| --- | --- |
| **Authentication** | Argon2id passwords with a parameter-upgrade path, TOTP with durable replay prevention, single-use recovery codes, WebAuthn passkeys with sign-counter clone detection |
| **Sessions** | Bounded, revocable contexts; the secret is stored only as a digest; revocation is durable and cascades to refresh-token families |
| **Authorization** | Deterministic default-deny decisions over roles, grants, groups, and bounded context conditions, with stable reasons and a versioned policy snapshot |
| **OAuth 2.0 / OIDC** | Authorization code with mandatory PKCE, rotating refresh families with reuse detection, discovery, JWKS, introspection, revocation, consent, RP-initiated logout |
| **Host adapters** | Versioned framework-neutral dispatch for seven OIDC endpoints; duplicate-preserving inputs, redacted errors, bounded responses, and one typed method in every SDK |
| **Federation** | Inbound OIDC federation, and inbound SAML 2.0 with an in-tree XML canonicalizer that refuses every ambiguous document |
| **Provisioning** | SCIM 2.0 users and groups, idempotent under directory reconciliation |
| **Durability** | A hash-chained security ledger on FYLO with rebuildable projections, verified snapshots, and restart evidence run against a real FYLO runtime |

85 operations across 18 families, one canonical manifest, and ten language SDKs
that each carry a typed method for every one of them.

## What is not claimed

This matters more than the list above. Nothing here is called supported until
code, negative-path tests, operator documentation, and recovery evidence exist
for it.

| Not claimed | Why |
| --- | --- |
| **OpenID certification** | The conformance profiles drive real browser redirects against a deployed host, and that suite has not been run. SESAME implements OIDC; it is not certified. |
| **Broad SAML interoperability** | The full flow is proven against pinned Keycloak 26.0. Other providers, including Okta, Entra ID, Google Workspace, Shibboleth, and ADFS, remain unproven. |
| **Production support** | Developer preview. A repeatable restore, upgrade/rollback, and soak evidence runner now exists, but no release has passed its 72-hour native gate or an independent security review. No version is supported for production use. |
| **High availability** | One host process owns one engine and one FYLO root. Active-active waits on coordination and replication semantics FYLO does not offer yet. |
| **Platform support** | A cross-compiled binary is not support. A platform is claimed only with native packaging, crash, restore, and upgrade evidence run on that operating system. |

## The machine protocol

One NDJSON request per line on stdin, one response per line on stdout.

```text
{"protocol_version":"1","request_id":"1","operation":"authorize.decide","parameters":{...}}
{"protocol_version":"1","request_id":"1","ok":true,"result":{"decision":"deny","reason_code":"deny_no_grant"}}
```

`api/machine/v1/operations.json` is the canonical surface, and
[`test/contract`](test/contract) asserts it four ways: against the engine's
dispatch table (parsed from the source), against the protocol reference,
against every SDK's source, and against the website. Adding an operation
without updating the manifest fails the build.

Error codes are a compatibility boundary — branch on the code, never the
message. The full reference is at
[sesame.del.ma/docs/errors](https://sesame.del.ma/docs/errors).

Public HTTP frameworks use the independently versioned
[host-adapter contract](api/standards/v1/README.md). The binary owns OAuth
request validation and response mapping; adapters only preserve bounded request
values and apply the returned instructions.

## SDKs

Ten thin shims, each a single standard-library-only file that spawns the engine
and speaks the protocol. None reimplements identity, authentication, or
authorization semantics. All ten run the same contract scenario against real
compiled binaries in CI, so a divergence fails the language that drifted.

| Language | Client | Runtime dependencies | File to copy |
| --- | --- | --- | --- |
| Go | [`clients/go`](clients/go/README.md) | none (stdlib) | none — `go get` at the tag |
| Node/TS | [`clients/node`](clients/node/README.md) | none (stdlib) | `node/sesame.mjs` |
| Python | [`clients/python`](clients/python/README.md) | none (stdlib) | `python/sesame.py` |
| Rust | [`clients/rust`](clients/rust/README.md) | none (std) | `rust/sesame.rs` |
| Java | [`clients/java`](clients/java/README.md) | none (JDK) | `java/Sesame.java` |
| Kotlin | [`clients/kotlin`](clients/kotlin/README.md) | `kotlin-stdlib` | `kotlin/Sesame.kt` |
| C# | [`clients/csharp`](clients/csharp/README.md) | none (BCL) | `csharp/Sesame.cs` |
| PHP | [`clients/php`](clients/php/README.md) | none (ext-json) | `php/sesame.php` |
| Ruby | [`clients/ruby`](clients/ruby/README.md) | none (stdlib) | `ruby/sesame.rb` |
| Dart | [`clients/dart`](clients/dart/README.md) | none (SDK) | `dart/sesame.dart` |

SDKs are distributed the way [FYLO](https://fylo.del.ma) distributes its own:
each release ships `sesame-clients.tar.gz` beside the engine binaries, and you
copy the one file for your language into your project. **There is no package
registry and no per-ecosystem manifest** — one release, one version, one
provenance chain, and no publishing credentials to hold. Go is the single
exception, since it lives in the engine's module.

```bash
curl -fsSL https://github.com/d31ma/sesame/releases/latest/download/sesame-clients.tar.gz | tar -xz
```

`tools/verify-sdk-install.sh` extracts that tarball and copies each shim into a
throwaway project for all ten languages, so every install instruction in these
READMEs is one CI executes. [docs/SDK_DISTRIBUTION.md](docs/SDK_DISTRIBUTION.md)
covers verification and what the model costs.

Kotlin and Dart are server-side clients here. FYLO ships them as on-device
clients that embed its engine; SESAME spawns its binary instead, so the same
languages are supported for JVM and Dart backends. There is deliberately no
browser, iOS, Android, or Flutter client: SESAME is a supervised server-side
process with no embeddable engine, and an on-device copy could never be
authoritative for shared security state.

## Design commitments

- Default deny, and fail closed. Missing, stale, or ambiguous security state is
  never an implicit allow.
- Tenant scope is explicit at every boundary, and enforced below
  caller-controlled query construction.
- Authentication flows are typed, versioned, persisted state machines rather
  than arbitrary scripts.
- Authorization decisions are deterministic, explainable, and auditable.
- A committed security transition and its audit evidence are the same durable
  event.
- FYLO/TTID identifiers are never used as secrets.
- Protocol support requires negative tests and applicable conformance suites.
- Credentials are read from environment variables, never flags, so they stay
  out of shell history and process listings.

## Testing

```bash
go test ./...           # 472 test functions
go test -race ./...
go vet ./...
go build -trimpath ./cmd/sesame

# Coverage is gated per package group rather than by one module-wide number,
# which would be either meaningless or immediately red.
go test -covermode=set -coverprofile=coverage.out ./internal/...
go run ./tools/coverage -profile coverage.out
```

| Group | Floor | Today |
| --- | --- | --- |
| `internal/domain` | 80% | 82.1% |
| `internal/application` | 75% | 77.7% |
| `internal/adapters` | 68% | 71.1% |
| `internal/platform` | 30% | 33.1% |

Each floor sits just below where the group stands, so this is a ratchet
against regression rather than an aspiration. Raising one is a deliberate
edit.

Two suites are worth knowing about. [`test/adversarial`](test/adversarial) runs
38 attack families against a **real compiled binary** over the shipped protocol
against a real deployment with real keys — a defence that exists only inside a
package boundary does not count. [`test/fylo`](test/fylo) carries restart,
recovery, and crash-boundary evidence against a real FYLO runtime; it is opt-in
because that runtime is a separate artifact:

```bash
SESAME_FYLO_INTEGRATION=1 SESAME_FYLO_PROFILE=full \
  FYLO_BINARY=/absolute/path/to/fylo \
  go test -count=1 ./test/fylo
```

## Repository shape

```text
cmd/sesame/                 engine and operator CLI
internal/
  domain/                   identity, authn, authz, session, oidc, saml, scim
  application/              commands, queries, and orchestration
  adapters/                 FYLO, machine protocol, crypto, and clock
  platform/                 deployment, CLI, logging, and build metadata
api/machine/v1/             the canonical operation manifest and reference
api/standards/v1/           the framework-neutral public-route contract
clients/                    ten SDK shims
test/                       contract, adversarial, and real-FYLO evidence
docs/                       ADRs, RFCs, operations, and security guidance
examples/hostserver/        the host side of the interaction contract
website/                    the source for sesame.del.ma
```

There is deliberately no `web/` tree and no standalone HTTP listener. Operators
use the CLI; applications use SDKs; the host application maps standards
endpoints onto versioned protocol operations. A future UI must be a separate
consumer of those public contracts and must never become a privileged bypass.

## Status

The core identity, authorization, authentication, OIDC, SDK, inbound
federation, SCIM, SAML, device authorization, PAR, and DPoP slices are
implemented. The framework-neutral host contract is implemented and proven by
the Go reference host; native examples for SvelteKit, Next.js, Nuxt, and Solid
remain.

Open gates are tracked in [the project plan](docs/PROJECT_PLAN.md): official
OpenID conformance, the first real deprecation cycle, packaged native
qualification, the 72-hour production-evidence matrix, and independent
security assessment. LDAP and proxy gateways remain deferred. Phase 7 scale
and HA remains blocked on coordination and replication semantics from FYLO.

## Documentation

**Guides** — [Configuration and keys](docs/CONFIGURATION.md) ·
[Inbound OIDC federation](docs/FEDERATION.md) ·
[SCIM 2.0 provisioning](docs/PROVISIONING.md) ·
[Inbound SAML 2.0](docs/SAML.md) ·
[SDK distribution](docs/SDK_DISTRIBUTION.md)

**Reference** — [Machine protocol](api/machine/v1/README.md) ·
[Host-adapter contract](api/standards/v1/README.md) ·
[Machine protocol RFC](docs/rfcs/0001-machine-protocol-v1.md) ·
[Host-adapter RFC](docs/rfcs/0002-host-adapter-contract-v1.md) ·
[Engineering standards](docs/ENGINEERING_STANDARDS.md) ·
[Release engineering](docs/RELEASE_ENGINEERING.md)

**Design** — [Project plan](docs/PROJECT_PLAN.md) ·
[Threat model](docs/THREAT_MODEL.md) · [Domain context](CONTEXT.md) ·
[Core language ADR](docs/adr/0001-core-language-and-runtime.md) ·
[FYLO persistence ADR](docs/adr/0002-fylo-persistence-boundary.md) ·
[Headless binary ADR](docs/adr/0003-headless-binary-and-client-contract.md) ·
[Federation egress ADR](docs/adr/0004-federation-egress-boundary.md) ·
[SAML signature ADR](docs/adr/0005-saml-signature-verification.md)

**FYLO** — [Viability evidence](docs/fylo/VIABILITY.md) ·
[Native evidence matrix](docs/fylo/NATIVE_MATRIX.md)

**Project** — [Website source](website/README.md) ·
[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) ·
[Changelog](CHANGELOG.md) · [Governance](GOVERNANCE.md) ·
[Code of conduct](CODE_OF_CONDUCT.md)

## The open gate

The full FYLO proving profile implements race-safe identifier claims,
single-use code and refresh-token redemption, a hash-chained ledger, verified
snapshots, revocation and replay equivalence, crash-boundary recovery, index
rebuild, cold local restore, corruption detection, schema upcasting, bounded
mixed admission, cancellation, restart, and latency/leak reporting. The macOS
arm64 development candidate has passed it repeatedly.

FYLO v26.30.06 supplies immutable release identity and a provisioned S3 release
gate. The Phase 1 gate remains open for FYLO-native internal transaction-crash
evidence, a packaged SESAME artifact, remote deployment restore, native runs on
every claimed platform and filesystem, and sustained release-profile capacity
results. See the [native evidence matrix](docs/fylo/NATIVE_MATRIX.md).

If that gate fails, SESAME will improve FYLO rather than weaken identity
invariants.

Production qualification is independently reproducible with
`tools/production-evidence`: it verifies allow and revoked-deny state after a
cold restore, exercises actual previous/current binaries in both directions,
and records explicit latency, error, heap, goroutine, and disk-growth limits.
The short native smoke observation and the remaining 72-hour, remote-backup,
packaging, platform-matrix, and independent-review gates are documented in
[Production Evidence](docs/PRODUCTION_EVIDENCE.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
