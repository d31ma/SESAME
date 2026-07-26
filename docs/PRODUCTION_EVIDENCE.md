# Production Evidence

SESAME remains an unsupported developer preview. This document describes the
repeatable evidence runner for three prerequisites to a future supported
release: restore drills, stored-data upgrade/rollback fixtures, and sustained
load limits. Passing the runner does not replace the rest of the native matrix
or an independent security assessment.

## Evidence runner

`tools/production-evidence` creates mode-`0700` deployments only below the
operating system's temporary directory. It never accepts an operator data root
and removes only the temporary workspace it created. The runner emits one JSON
report containing:

- SHA-256, size, and runtime identity for the exact SESAME and FYLO artifacts;
- native operating system, architecture, logical CPU count, and an
  operator-supplied reference-environment label;
- restored allow and revoked-deny outcomes;
- previous-to-current upgrade and current-to-previous rollback outcomes;
- operation count, write count, error ratio, throughput, p50/p95/p99 latency,
  child-process heap and goroutine growth, and deployment disk growth;
- every configured pass/fail limit and every limitation on the result.

The runner has two profiles:

- `smoke` permits a short local run, may omit a previous SESAME binary, and is
  never eligible as release evidence;
- `release` requires distinct previous and current artifacts, immutable release
  metadata, a signed-release FYLO identity, an environment label, enforced
  resource limits, and a soak of at least 72 hours.

A development binary, an unversioned commit, a short duration, observational
resource metrics, or the same artifact supplied as both versions cannot pass a
release-profile run.

## Restore drill

The runner creates a complete SESAME deployment, records two authorization
histories, and stops the process:

1. one principal retains an applicable role grant and must be allowed;
2. one principal receives the same grant and then has it durably revoked, and
   must be denied.

It copies the stopped deployment—including its FYLO root and external key
directory—into a distinct root, starts an independent SESAME process there,
resolves both principals again, and requires the same allow and deny outcomes.
This catches a restore that loses policy, grant revocation, the authoritative
event chain, snapshot state, or deployment keys.

This is a cold local restore. A provisioned S3-compatible FYLO
backup/verify/restore run and a separately protected deployment-key backup
remain required production-environment evidence.

## Upgrade and rollback fixture

When `--previous-sesame-binary` is supplied, the runner:

1. initializes and seeds a deployment through the previous binary;
2. opens it with the current binary and verifies the baseline decisions;
3. writes a compatibility marker through the current binary;
4. reopens the same deployment with the previous binary;
5. requires both the original decisions and the current binary's marker to be
   visible.

This is a black-box stored-data fixture made by the actual previous executable,
not a hand-authored imitation of FYLO records. Each supported stored-data
version must be retained as an immutable release artifact and exercised this
way. The current fixture covers tenant, principal, role, grant, and revocation
state; it must expand with every supported stored event type before it can
represent the complete stored-data surface. A release for which backward replay
is unsafe must declare rollback unsupported and provide a tested restore-based
rollback procedure instead of silently skipping this stage.

## Soak workload and limits

The workload uses the public Go SDK against a real SESAME subprocess. It mixes
authorization decisions with periodic durable principal creation, so the run
measures both the read path and ledger/snapshot growth. `system.metrics`
provides heap and goroutine observations from the SESAME child itself; the
runner independently walks the complete temporary deployment to measure disk
growth. Latencies enter a fixed-size logarithmic histogram with 32 buckets per
power of two and report the selected bucket's upper bound. The runner therefore
does not retain one sample per operation or grow its own memory with soak
duration.

Release thresholds are not hard-coded before reference hardware and a
supported deployment size are selected. The release invocation must state
them explicitly. That keeps an observed number from quietly becoming a product
commitment.

## Reproduce a smoke run

Build a native SESAME binary and use the exact pinned FYLO release artifact:

```bash
go build -trimpath -o /absolute/path/to/sesame ./cmd/sesame

go run ./tools/production-evidence \
  --profile smoke \
  --sesame-binary /absolute/path/to/sesame \
  --fylo-binary /absolute/path/to/fylo \
  --environment-label "local smoke; OS/architecture; filesystem; storage" \
  --soak-duration 5m \
  --min-operations 1000 \
  --enforce-resource-limits \
  --max-p99 250ms \
  --max-heap-growth-bytes 268435456 \
  --max-goroutine-growth 10 \
  --max-deployment-growth-bytes 1073741824
```

Use a natively built `production-evidence` executable when the installed Go
toolchain targets a different architecture than the host. The report's
`platform` and each artifact's runtime identity expose such a mismatch; do not
describe a translated or cross-architecture run as native.

## Current smoke observation

On 2026-07-26, a five-second smoke run passed natively on `darwin/arm64`
against the signed FYLO v26.30.06 `fylo-macos-arm64` artifact with SHA-256
`ae39a2b66ea9771766f3f3d6b3d0d1b01e1b3842a45aa0389535109b91bdee50`.
The SESAME artifact was a development build, so the result is not release
evidence. The run observed:

- cold restore preserved `allow_role_grant` and the revoked
  `deny_no_grant` decision;
- 4,441 operations, including 223 durable writes, with zero operation errors;
- 884.93 operations/second and p50/p95/p99 upper bounds of
  0.033/19.106/22.234 ms;
- zero goroutine growth, a negative post-GC heap delta, and 31,550,109 bytes of
  deployment growth.

The short duration, disposable APFS root, development SESAME metadata, omitted
previous binary, and absent remote-backup drill make these implementation smoke
observations—not supported limits.

## Remaining production-support gates

- run upgrade and rollback against two distinct immutable SESAME releases and
  expand the fixture across every supported stored event type;
- select reference hardware and workload sizes, then publish reviewed limits;
- pass the 72-hour release profile on every candidate native target;
- exercise provisioned remote backup/verify/restore plus deployment-key
  recovery and measure RTO/RPO;
- complete packaged install, crash, recovery, native filesystem, SDK
  interoperability, and upgrade matrix rows;
- complete an independent security assessment and own every critical finding.
