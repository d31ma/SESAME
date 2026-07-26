# Contributing to SESAME

SESAME is security infrastructure. Contributions are welcome, but correctness,
compatibility, and recovery evidence take priority over feature volume.

## Prerequisites

- Go 1.26.5 or the toolchain selected by `go.mod`;
- Git;
- a local clone outside a synchronized data root for persistence tests.

The core has no third-party runtime dependency yet. FYLO, CHEX, and TTID will be
pinned when the viability harness is introduced.

## Local Checks

Run the smallest relevant test first, then the complete gate:

```bash
gofmt -w cmd internal clients test
go test ./...
go test -race ./...
go vet ./...
go build -trimpath ./cmd/sesame
```

CI additionally runs `staticcheck`, `govulncheck`, native operating-system
tests, and cross-compilation checks.

## Change Requirements

- Begin behavior changes with an observable failing test.
- Keep changes vertically complete across contracts, implementation, negative
  paths, documentation, and migration behavior.
- Do not add an empty package or speculative abstraction.
- Update JSON Schema, machine fixtures, framework adapters, and SDKs together
  when a public contract changes.
- Preserve public API and stored-data compatibility unless an accepted ADR/RFC
  defines the break and migration.
- Add threat-model coverage for changes involving credentials, sessions,
  tokens, policy, tenancy, federation, persistence, recovery, or privileged
  operations.
- Never weaken or skip a security test to make CI pass.

## Pull Requests

Describe:

1. the behavior and security invariant being changed;
2. failure modes and public compatibility impact;
3. tests and operating systems used as evidence;
4. documentation, migration, and rollback implications.

Keep generated output separate from unrelated hand-written refactors. Remove
debug output, stale fixtures, commented-out code, and sample secrets before
requesting review.

## Licensing

SESAME is licensed under Apache-2.0. Unless explicitly stated otherwise, an
intentional contribution is submitted under the same license as described in
Section 5 of `LICENSE`. The project does not currently require a separate CLA.
