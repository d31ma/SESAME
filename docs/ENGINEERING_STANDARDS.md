# SESAME Engineering Standards

## Purpose

SESAME is security infrastructure. Its repository and code should make ownership,
trust boundaries, failure behavior, and compatibility obvious to a new
contributor. “Enterprise-grade” means repeatable engineering evidence, not a
large number of folders or abstractions.

## Repository Rules

- Build vertical slices. Add a package only with production behavior and tests.
- Keep domain code independent of host frameworks, NDJSON, FYLO, SDKs,
  configuration, and operating-system details.
- Place executable entry points under `cmd/sesame`.
- Keep non-public Go implementation under `internal`.
- Store canonical wire contracts under `api`; generated artifacts must identify
  their source and must never be edited by hand.
- Keep client shims under `clients/<language>` with independent manifests,
  tests, examples, and release metadata.
- Put black-box and system-wide tests under `test`; package-local tests remain
  beside the Go code they exercise.
- Record hard-to-reverse choices in ADRs and proposed public behavior in RFCs.
- Do not add empty placeholder directories.
- Do not create generic dumping grounds named `utils`, `helpers`, `common`,
  `shared`, `misc`, `base`, or `manager`.

## Go Naming and Layout

- Package names are short, lowercase, singular domain terms.
- Go files use `lower_snake_case.go`; tests end in `_test.go`.
- Name files by their responsibility, not their layer number or ticket.
- Export only deliberate package contracts. Document every exported symbol.
- Prefer unexported concrete types and small interfaces owned by their consumer.
- Avoid interface names prefixed with `I`.
- Use domain names consistently: principal, authenticator, session, client,
  resource, action, policy, decision, tenant.
- Do not interchange `user`, `account`, `identity`, and `principal`.
- Avoid suffixes such as `Impl`, `Util`, `Helper`, `Manager`, and `Common`.

## Go Coding Rules

- Run `gofmt`; import ordering is automated.
- Pass `context.Context` first to blocking, cancellable, or request-scoped
  operations. Never store it in a long-lived struct.
- Return errors; do not panic on untrusted input, expected failure, or operator
  configuration.
- Wrap errors with useful operation context while preserving machine-testable
  types/codes.
- Constructors validate required dependencies and configuration.
- Avoid mutable package globals and side-effectful `init` functions.
- Use explicit dependency injection through constructors.
- Prefer composition and simple control flow over framework-heavy indirection.
- Keep I/O at boundaries and domain transitions deterministic.
- Use an injected clock and random source where deterministic tests require it;
  production cryptographic randomness must remain non-substitutable by callers.
- Bound all input, queues, concurrency, retries, recursion, and external reads.
- Close files, response bodies, child-process pipes, and goroutines on every
  path.
- Zero or minimize secret lifetimes where practical. Never format secrets into
  errors, logs, traces, metrics, or audit fields.
- Comments explain invariants and non-obvious tradeoffs, not syntax.

## Public Contract Rules

- JSON Schema, machine fixtures, standards-dispatch fixtures, and stable error
  codes are canonical.
- Public API fields use `snake_case` JSON names.
- Identifiers are opaque strings. Clients never infer type, time, tenancy, or
  authorization from their shape.
- Additive compatibility is preferred within a major version.
- A breaking change requires an ADR/RFC, migration path, deprecation window,
  compatibility tests, and major contract version.
- Unknown-field, enum-extension, and protocol-minor behavior must be explicit.
- Every mutating operation documents idempotency and safe retry semantics.
- Errors expose a stable code, safe message, retryability, and bounded details.
- Human-readable text is not a parsing contract.
- Generated SDK code includes a generated header and reproducible command.
- SDKs never expose internal FYLO records or SESAME event schemas as their
  primary application API.

## Security and Reliability Rules

- Default deny and fail closed.
- Validate tenant scope below caller-controlled query construction.
- Serialize all uniqueness and single-use transitions against current
  authoritative state.
- Treat parser, protocol, storage, crypto, clock, filesystem, process, and
  network inputs as untrusted.
- Use standard cryptography and reviewed protocol libraries; never invent a
  construction.
- Prefer constant-time secret verification where observation is possible.
- Require algorithm allowlists, bounded lifetimes, exact redirect matching, and
  deliberate key rotation.
- Make every acknowledged security transition durable before success.
- Make every background workflow durable, observable, retry-safe, and bounded.
- Do not downgrade a failure to improve availability when doing so can grant
  access or lose revocation.

## Test Standards

Every behavior starts with an observable test at the narrowest stable boundary.

- Unit tests cover deterministic domain behavior.
- Table/property/model tests cover state spaces and invariants.
- Integration tests use the pinned real FYLO executable.
- Contract tests exercise CLI, NDJSON, host-framework adapters, and SDK parity.
- Race tests cover mutable shared state.
- Fuzz tests cover all parsers and security boundaries.
- Crash tests inject termination around every durable acknowledgement boundary.
- Recovery tests destroy derived state and prove rebuild equivalence.
- Upgrade tests start from every supported stored-data version.
- Security tests include malformed, replayed, expired, revoked, cross-tenant,
  stale, concurrent, and resource-exhaustion cases.

Tests must be deterministic unless they are explicitly load, chaos, fuzz, or
soak tests. A flaky security test is a release blocker for the claim it protects.

## Tooling Baseline

The initial Go gate should include:

- `gofmt`;
- import ordering;
- `go vet`;
- `staticcheck`;
- `go test`;
- `go test -race` where supported;
- native Go fuzzing;
- `govulncheck`;
- dependency/license policy;
- generated-contract drift check;
- secret scanning.

The canonical local commands are documented in `CONTRIBUTING.md`, `AGENTS.md`,
and `CLAUDE.md`. CI is authoritative for pinned static-analysis and
vulnerability-tool versions.

Add linters only when each rule is understood and accepted. A huge inherited
lint profile that contributors routinely suppress is not an enterprise control.

## Review Expectations

- Keep pull requests vertically complete and small enough to audit.
- State the security invariant, failure modes, public compatibility impact, and
  evidence in every material change.
- Require security review for credentials, sessions, tokens, policy, tenancy,
  federation, recovery, storage, key custody, and privileged operations.
- Preserve public API and stored-data compatibility unless a reviewed migration
  intentionally changes them.
- Never mix generated changes with unrelated hand-written refactors.
- No commented-out code, debug output, stale fixtures, unowned TODOs, or sample
  secrets ship.
