# ADR 0001: Core Language and Runtime

- Status: Accepted
- Date: 2026-07-23
- Accepted: 2026-07-26

## Context

SESAME is a security-critical identity engine that processes network-originated
data forwarded by its host application. It needs strong types, predictable
concurrency, mature protocol and cryptographic primitives, a small deployment
artifact, straightforward operations, and a contributor experience that does
not require the multi-language toolchain used by authentik.

FYLO exposes a persistent NDJSON machine interface and ships a Go client, so the
engine language does not need to embed FYLO's JavaScript source.

## Decision

Use Go 1.26 for the engine, operator CLI, protocol processing, policy engine,
background work, and local machine interface.

SESAME ships no web or desktop UI in the initial product scope. TypeScript is
used only where appropriate for the Node SDK; it is not part of the engine
runtime.

Pin the latest security patch of Go 1.26 in CI and release builds. At the time of
this decision, that is Go 1.26.5.

Keep the Go engine a modular monolith for v1. Modules communicate through typed
in-process interfaces. Do not introduce internal microservices until a measured
scaling or isolation boundary requires them.

## Why Go

| Criterion | Go | Rust | TypeScript/Bun |
| --- | --- | --- | --- |
| Memory and type safety | Strong | Strongest | Strong types at compile time, dynamic runtime |
| Protocol/crypto standard library | Excellent | Good, more ecosystem assembly | Good, more third-party surface |
| Concurrency model | Simple and operationally familiar | Powerful, higher complexity | Simple I/O model, single event loop by default |
| Single-binary operations | Excellent | Excellent | Possible with Bun |
| FYLO integration | Official persistent client | Official persistent client | Best escape hatch into FYLO internals |
| Contributor learning curve | Low to moderate | Higher | Low |
| Delivery risk for a small team | Low | Moderate to high | Moderate for security-critical core |

Go is the best overall risk tradeoff. Rust remains suitable for isolated
cryptographic or high-throughput components if profiling proves a need.
TypeScript remains appropriate for the Node client, but using it for the core
would make it too tempting to couple SESAME to FYLO's private JavaScript
internals.

## Consequences

- The core contributor path requires only Go and a pinned FYLO binary.
- Each client SDK has its own optional language toolchain and release lifecycle;
  contributors do not need every SDK toolchain to work on the core.
- The FYLO machine protocol becomes an explicit typed boundary.
- Protocol and crypto dependencies still require security review; language
  safety does not make protocol composition safe.
- The Go FYLO client currently serializes calls through one long-lived process.
  The viability gate must measure that bottleneck.
- Each release target is a platform-specific executable. There is no single
  executable format that runs unchanged on Linux, macOS, and Windows.
- The absence of a bundled interaction UI means browser-based authentication
  requires a separately deployed, trusted interaction client.

## Rejected Alternatives

- **Rust for the whole service**: excellent safety and performance, but slower
  delivery, more async complexity, and a smaller identity-protocol contributor
  pool for the initial team.
- **TypeScript/Bun for the whole service**: excellent FYLO affinity and code
  sharing, but a broader dependency/runtime attack surface and pressure to use
  FYLO implementation internals instead of a stable contract.
- **Python/Django**: mature identity ecosystem, but it would recreate much of
  authentik's operational and performance profile rather than differentiate
  SESAME.

## Acceptance Gate

This ADR becomes Accepted only when the FYLO proving ground shows that the Go
machine-protocol boundary can satisfy the state-transition correctness,
recovery, and performance gates in `docs/PROJECT_PLAN.md`.
